import asyncio
from datetime import datetime
import os
from typing import Annotated
import bcrypt
import uuid


from fastapi import FastAPI, Request, Form, Cookie, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import redis.asyncio as aioredis
import asyncpg


load_dotenv()

MAX_RETRIES = 10
RETRY_DELAY = 3
INIT_DB_SCRIPT = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
"""


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_redis():
    return app.state.redis

def get_postgres():
    return app.state.pg_pool

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


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request, session_id: Annotated[str, Depends(verify_session)]):
    return RedirectResponse(url="/analysis", status_code=303)




@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    redis: aioredis.Redis = Depends(get_redis),
    pool: aioredis.Redis = Depends(get_postgres)
    ):

    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            "SELECT id, password_hash FROM users WHERE username = $1 LIMIT 1", 
            username
        )

    # 2. Если пользователь не найден или пароль не совпал -> отдаем 401
    if not user_row or not verify_password(password, user_row["password_hash"]):
        return RedirectResponse(url="/login?error=Неверный+логин+или+пароль", status_code=303)


    user_id = user_row["id"]

    session_token = str(uuid.uuid4())
    redis_key = f"session:{session_token}"

    await redis.hset(redis_key, mapping={
        "id": str(user_id),
        "username": username,
        #"time": datetime.now(timezone.utc).isoformat()  
    })
    await redis.expire(redis_key, 3600)

    response = RedirectResponse(url="/analysis", status_code=303)
    response.set_cookie(key="session_id", value=session_token, httponly=True, max_age=3600)

    return response





@app.get("/analysis", response_class=HTMLResponse)
async def analysis_page(request: Request, session_id: Annotated[str, Depends(verify_session)]):
    return templates.TemplateResponse("analysis.html", {
        "version": VERSION,
        "request": request,
        "all_columns": ALL_COLUMNS,
        "default_enabled": DEFAULT_ENABLED,
        "table_data": MOCK_DATA
    })

@app.post("/analysis/new")
async def create_analysis(
    session_id: Annotated[str, Depends(verify_session)],
    task_name: str = Form(...),
    scan_type: str = Form(...),
    environment: str = Form(...)
):
    # Тут будет твоя логика запуска (например, дерганье Guacamole/VNC или сканера)
    print(f"Запуск нового анализа: {task_name} ({scan_type}) в среде {environment}")
    
    # После создания редиректим обратно на таблицу
    return RedirectResponse(url="/analysis", status_code=303)

@app.get("/analysis/{task_uuid}/results", response_class=HTMLResponse)
async def task_results(task_uuid: str, session_id: Annotated[str, Depends(verify_session)]):
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



