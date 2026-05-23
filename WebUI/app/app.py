from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import uuid

app = FastAPI()
templates = Jinja2Templates(directory="templates")

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


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    # Рендерим страницу логина. Если есть ошибка — передаем её в шаблон
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(
    username: str = Form(...), 
    password: str = Form(...)
):
    # Простейшая проверка учетных данных
    if username == DUMMY_USERNAME and password == DUMMY_PASSWORD:
        # При успехе редиректим на главную (где потом будет твой Guacamole)
        return RedirectResponse(url="/analysis", status_code=303)
    
    # Если данные неверны, возвращаем на /login с флагом ошибки
    return RedirectResponse(url="/login?error=Неверный+логин+или+пароль", status_code=303)

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    # Заглушка для главной страницы после успешного входа
    return RedirectResponse(url="/login", status_code=303)
    return HTMLResponse("<h1>Успешный вход! Тут будет панель управления VNC.</h1>")





@app.get("/analysis", response_class=HTMLResponse)
async def analysis_page(request: Request):
    return templates.TemplateResponse("analysis.html", {
        "request": request,
        "all_columns": ALL_COLUMNS,
        "default_enabled": DEFAULT_ENABLED,
        "table_data": MOCK_DATA
    })

@app.post("/analysis/new")
async def create_analysis(
    task_name: str = Form(...),
    scan_type: str = Form(...),
    environment: str = Form(...)
):
    # Тут будет твоя логика запуска (например, дерганье Guacamole/VNC или сканера)
    print(f"Запуск нового анализа: {task_name} ({scan_type}) в среде {environment}")
    
    # После создания редиректим обратно на таблицу
    return RedirectResponse(url="/analysis", status_code=303)

@app.get("/analysis/{task_uuid}/results", response_class=HTMLResponse)
async def task_results(task_uuid: str):
    # Страница результатов конкретного UUID
    return HTMLResponse(f"<h1>Результаты для анализа с UUID: {task_uuid}</h1><a href='/analysis'>Назад к таблице</a>")

@app.get("/logoff")
async def logoff():
    # Простая деавторизация — отправка на страницу логина
    return RedirectResponse(url="/login", status_code=303)


