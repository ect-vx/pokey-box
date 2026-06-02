import asyncio
from datetime import datetime
import os
from typing import Annotated
import bcrypt
import uuid
from datetime import datetime, timezone
import json

from guapy import create_server
from guapy.guacd_client import GuacdClient
from guapy.client_connection import ClientConnection
from guapy.models import ClientOptions, CryptConfig, GuacdOptions
from guapy.crypto import GuacamoleCrypto

from fastapi import FastAPI, Request, Form, Cookie, Depends, HTTPException, WebSocket, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import redis.asyncio as aioredis
import asyncpg


# TODO: работа с часовыми поясами через depends, а не захардкоженный UTC +7 
# TODO: TTL в редисе
# TODO: pydantic для систематизации данных в БД
# TODO: разбить код логически по нескольким файлам


# жизнь сессии в редисе = 3600 сек
# жизнь анализа в редисе = 3600 сек - надо реализовать

load_dotenv()

SECRET_GUACD = "my_super_secret_key_32_bytes12!!"
crypto = GuacamoleCrypto(cipher_name="AES-256-CBC", key=SECRET_GUACD)
GUACD_OPTIONS = GuacdOptions(host="pokey-guacd", port=4822)

MAX_RETRIES = 10
RETRY_DELAY = 3
INIT_DB_SCRIPT = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id UUID PRIMARY KEY,
    sample_hash VARCHAR(64),
    scan_type SMALLINT,
    status SMALLINT DEFAULT 0,
    verdict VARCHAR(50) DEFAULT 'Unknown',
    created_at VARCHAR(64) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS artifacts (
    id BIGSERIAL PRIMARY KEY,
    analysis_id UUID,
    artifact_key VARCHAR(255),
    path TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
"""

# INSERT INTO analyses (id, status, environment_id, created_at) VALUES ($1, $2, $3, $4)
# analyses
#        +----------------+--------------------------+
#        | ПОЛЕ           | ТИП ДАННЫХ               |
#        +----------------+--------------------------+
#   PK --| id             | UUID                     | <---+
#    ? --| sample_hash    | VARCHAR(64)              |     |
#        | scan_type      | SMALLINT                 |     |
#        | status         | SMALLINT                 |     | Связь по UUID
#        | verdict        | VARCHAR(50)              |     |
#        | created_at     | TIMESTAMP WITH TIME ZONE |     |
#        +----------------+--------------------------+     |
#                                                          |
#                                                          |
#        analysis_artifacts                                |
#        +----------------+--------------------------+     |
#        | ПОЛЕ           | ТИП ДАННЫХ               |     |
#        +----------------+--------------------------+     |
#   PK --| id             | BIGSERIAL                |     |
#        | analysis_id    | UUID                     | ----+
#        | artifact_key   | VARCHAR(255)             |
#        | path           | TEXT                     |
#        | created_at     | TIMESTAMP WITH TIME ZONE |
#        +----------------+--------------------------+
# await conn.execute("INSERT INTO users (username, password_hash) VALUES ($1, $2)", "1", hash_password("1"))


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_redis():
    return app.state.redis

async def get_postgres():
    async with app.state.pg_pool.acquire() as connection:
        yield connection

async def verify_session(
    session_id: Annotated[str | None, Cookie()] = None,
    redis: aioredis.Redis = Depends(get_redis)
) -> str:
    
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
        
    user_data = await redis.hgetall(f"session:{session_id}")
    
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
        
    return session_id



# return RedirectResponse(url="/login?error=Неверный+логин+или+пароль", status_code=303)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # postgres init
    pg_pool = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"Connecting to Postgres (attempt {attempt}/{MAX_RETRIES})...")
            pg_pool = await asyncpg.create_pool(
                os.environ.get("POSTGRES_URL"),
                min_size=5,
                max_size=20,
                command_timeout=60
            )
            # Connection verification query
            async with pg_pool.acquire() as conn:
                print("Checking and initializing database schema...", flush=True)
                await conn.execute(INIT_DB_SCRIPT)
                # await conn.execute("INSERT INTO users (username, password_hash) VALUES ($1, $2)", "1", hash_password("1"))
                # await conn.execute("INSERT INTO users (username, password_hash) VALUES ($1, $2)", "2", hash_password("2"))
            
            app.state.pg_pool = pg_pool
            print("Postgres connection pool initialized successfully.")
            break

        except (asyncpg.PostgresError, OSError, ConnectionRefusedError) as e:
            print(f"Postgres connection failed: {e}. Retrying in {RETRY_DELAY} seconds...")
            if pg_pool:
                await pg_pool.close()
            if attempt == MAX_RETRIES:
                print("Critical: Failed to connect to Postgres after maximum retries.")
                raise e
            await asyncio.sleep(RETRY_DELAY)

    # redis init
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"Connecting to Redis (attempt {attempt}/{MAX_RETRIES})...")
            redis_client = aioredis.from_url(
                os.environ.get("REDIS_URL"), 
                decode_responses=True,
                retry_on_timeout=True,
                socket_connect_timeout=5
            )
            # Connection verification ping
            await redis_client.ping()
            
            app.state.redis = redis_client
            print("Redis client initialized successfully.")
            break

        except (aioredis.RedisError, ConnectionRefusedError) as e:
            print(f"Redis connection failed: {e}. Retrying in {RETRY_DELAY} seconds...")
            if attempt == MAX_RETRIES:
                print("Critical: Failed to connect to Redis after maximum retries.")
                if hasattr(app.state, "pg_pool") and app.state.pg_pool:
                    await app.state.pg_pool.close()
                raise e
            await asyncio.sleep(RETRY_DELAY)
    

    # client_options = ClientOptions(
    #     crypt=CryptConfig(
    #         cypher="AES-256-CBC",
    #         key="MySuperSecretKeyForParamsToken12",
    #     ),
    #     max_inactivity_time=10000,
    # )

    # guacd_options = GuacdOptions(host="127.0.0.1", port=4822)
    # guapy_server = create_server(client_options, guacd_options)
    # app.state.guapy = guapy_server
    print("Initialization completed succesfully ()")
    yield
    await app.state.pg_pool.close()
    await app.state.redis.close()
    print("connections to db closed")


app = FastAPI(title="Pokey", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

VERSION = "0.0.1"


# Временная база данных для демонстрации кастомизации таблицы
ALL_COLUMNS = {
    "id": "ID Запуска",
    "name": "Название",
    "status": "Статус",
    "target": "Цель (IP/Хост)",
    "vulnerabilities": "Уязвимости",
    "date": "Дата создания"
}

# Колонки, которые видны по умолчанию
DEFAULT_ENABLED = ["id", "name", "status", "target", "date"]

# Хордкордные данные для теста (в реале тут будет база данных)
DUMMY_USERNAME = "1"
DUMMY_PASSWORD = "1"

# Тестовые данные для таблицы (строки)
MOCK_DATA = [
    {"id": str(uuid.uuid4())[:8], "name": "Сканирование сети офиса", "status": "Завершено", "target": "192.168.1.0/24", "vulnerabilities": "3 High, 5 Low", "date": "2026-05-20"},
    {"id": str(uuid.uuid4())[:8], "name": "Проверка веб-сервера", "status": "В процессе", "target": "https://test.local", "vulnerabilities": "0", "date": "2026-05-23"},
    {"id": str(uuid.uuid4())[:8], "name": "Тест Guacamole инстанса", "status": "Ошибка", "target": "10.0.0.5", "vulnerabilities": "N/A", "date": "2026-05-22"},
]




# @app.get("/root")
# async def root():
#     return {"message": "Hello, World!"}

# client_options = ClientOptions(
#     crypt=CryptConfig(
#         cypher="AES-256-CBC",
#         key="MySuperSecretKeyForParamsToken12",
#     ),
#     max_inactivity_time=10000,
# )
# guacd_options = GuacdOptions(host="127.0.0.1", port=4822)
# guapy_server = create_server(client_options, guacd_options)
# app.mount("/guapy", guapy_server.app)







@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request, session_id: Annotated[str, Depends(verify_session)]):
    return RedirectResponse(url="/analysis", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse(
        request=request, 
        name="login.html", 
        context={"error": error})


@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    redis: aioredis.Redis = Depends(get_redis),
    conn: aioredis.Redis = Depends(get_postgres)
    ):


    user_row = await conn.fetchrow(
        "SELECT id, password_hash FROM users WHERE username = $1 LIMIT 1",
        username
    )

    if not user_row or not verify_password(password, user_row["password_hash"]):
        return RedirectResponse(url="/login?error=Неверный+логин+или+пароль", status_code=303)

    user_id = user_row["id"]

    session_token = str(uuid.uuid4())
    redis_key = f"session:{session_token}"

    await redis.hset(redis_key, mapping={
        "id": str(user_id),
        "username": username,
        #"time": datetime.now(timezone.utc)
    })
    await redis.expire(redis_key, 3600)

    response = RedirectResponse(url="/analysis", status_code=303)
    response.set_cookie(key="session_id", value=session_token, httponly=True, max_age=3600)

    return response


@app.get("/analysis", response_class=HTMLResponse)
async def analysis_page(request: Request, session_id: Annotated[str, Depends(verify_session)]):
    return templates.TemplateResponse(
        request=request,
        name="analysis.html",
        context={
        "version": VERSION,
        "all_columns": ALL_COLUMNS,
        "default_enabled": DEFAULT_ENABLED,
        "table_data": MOCK_DATA
    })

@app.post("/analysis/new")
async def create_analysis(
    session_id: Annotated[str, Depends(verify_session)],
    # task_name: str = Form(...),
    scan_type: int = Form(...),
    # environment: str = Form(...),
    redis: aioredis.Redis = Depends(get_redis),
    conn = Depends(get_postgres)
    ):
    
    analysis_id = str(uuid.uuid4())
    analysis_data = {
        "scan_type":scan_type,
        "status":0,
        "created_at":datetime.now(timezone.utc).isoformat()
        }
    await conn.execute(
        """
        INSERT INTO analyses (id, status, scan_type, created_at) 
        VALUES ($1, $2, $3, $4);
        """, analysis_id, analysis_data["status"], analysis_data["scan_type"], analysis_data["created_at"]
    )

    redis_key = f"analysis:{analysis_id}"
    await redis.hset(name=redis_key, mapping=analysis_data)

    # print(f"Запуск нового анализа: {task_name} ({scan_type}) в среде {environment}")
    
    # TODO: Создать схему динамического выбора коробки через шаблонизацию
    # TODO: Ассинхронная передача в коробку анализа (сразу передавать то, что находится)
    return RedirectResponse(url=f"/analysis/{analysis_id}", status_code=303)



# TODO: использовать AJAX
@app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_results(
    request: Request,
    analysis_id: str,
    session_id: Annotated[str, Depends(verify_session)],
    redis: aioredis.Redis = Depends(get_redis),
    conn = Depends(get_postgres)
    ):

    redis_key = f"analysis:{analysis_id}"
    status: int = await redis.hget(name=redis_key, key="status")
    print(f"redi:{status}")
    if not status:
        row = await conn.fetchrow(
            "SELECT status FROM analyses WHERE id = $1 LIMIT 1",
            analysis_id
        )
        status: int = row[0]

    status = 3
    current_status = status

    match status:
        case 1 | 2 :        # init_box
            # TODO: загрузка
            pass
        case 3:             # box_ready
            # TODO: взять параметры подключения из редиса

            connection_info = {
                "connection": {
                    "type": "vnc",
                    "settings": {
                        "hostname": "192.168.2.208",
                        "port": 5900,
                        "width": 1280,
                        "height": 720,
                        "dpi": 96
                    }
                }
            }

            # json_data = json.dumps(connection_info)
            guacd_token = crypto.encrypt(connection_info)

            return templates.TemplateResponse(
                name="analysis_page.html",
                request=request,
                context={
                    "analysis": {
                        "id": analysis_id,
                        "status": status,
                        "token": guacd_token  # Передаем зашифрованный токен
                    }
                }
            )

        case 4 | 5 | 6:     # init_analysis
            # TODO: загрузка анализа (анализ начинается)
            pass
        case 7:             # analysis_pending
            # TODO: загрузка анализа (анализ идет в данный момент)
            pass
        case 8 | 9 | 10:    # analysis_stopping
            # TODO: загрузка анализа (анализ останавливается)
            pass
        case 11 | 0:        # done
            # TODO: вытягиваем результаты из постгре
            pass

        case 11:            # analysis ready
            # пока бессмысленный эндпоинт, нужен будет для ajax и загрузки
            pass
        case 0:             # done
            # пока бессмысленный эндпоинт, нужен будет для ajax и загрузки
            pass
        case 20:            # aborted
            # TODO: страница содержит оператора, который начал, 
            # причину прекращения анализа тайминг и сообщение о прекращении
            pass
        case a:
            print(f"unsupported status: {a}")
    
    analysis_data = {
        "id": str(analysis_id),
        "status": current_status, # Передаем числом
        "sample_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "environment_id": 1,
        "verdict": "Malicious",
        "guacd_token": "secret_guacamole_session_token_123",
        "artifacts": [
            {"artifact_key": "dropped_exe", "path": "C:\\Temp\\payload.exe"},
            {"artifact_key": "pcap_log", "path": "/var/log/traffic.pcap"}
        ] if current_status == 3 else []
    }

    return templates.TemplateResponse(
        request=request,
        name="analysis_page.html", 
        context={"analysis": analysis_data, "version": "0.0.1"}
    )

    # analysis_data = if await redis.hgetall(redis_key) then redis.hgetall(redis_key) else запрос к бд

    # response = RedirectResponse(url="/analysis", status_code=303)
    # response.set_cookie(key="session_id", value=session_token, httponly=True, max_age=3600)

    # return response
    
    # Страница результатов конкретного UUID
    return HTMLResponse(f"<h1>Результаты для анализа с UUID: {task_uuid}</h1><a href='/analysis'>Назад к таблице</a>")

@app.get("/logoff")
async def logoff(
    session_id: str | None = Cookie(None),
    redis: aioredis.Redis = Depends(get_redis)
    ):

    if session_id:
        await redis.delete(f"session:{session_id}")

    response = RedirectResponse(url="/analysis", status_code=303)
    response.set_cookie(key="session_id", value="", httponly=True, max_age=3600)

    return response



@app.websocket("/ws/tunnel")
async def guacamole_tunnel(websocket: WebSocket):
    # Инициализируем высокоуровневое соединение guapy
    # connection_id можно передавать статичный или генерировать uuid
    CLIENT_OPTIONS = ClientOptions(
        crypt=CryptConfig(
            cypher="AES-256-CBC",
            key=SECRET_GUACD)
    )

    connection = ClientConnection(
        websocket=websocket,
        connection_id=123, 
        client_options=CLIENT_OPTIONS,
        guacd_options=GUACD_OPTIONS
    )
    
    try:
        # Запускаем обработчик. Он сам считает ?token= из websocket.query_params,
        # расшифрует его, подключится к guacd и свяжет потоки.
        await connection.handle_connection()
    except Exception as e:
        print(f"Ошибка в туннеле Guacamole: {e}")