import hashlib, os, secrets, smtplib, ssl
from email.message import EmailMessage

import psycopg
from contextlib import asynccontextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel, EmailStr, Field

load_dotenv()
ROOT = Path(__file__).resolve().parent.parent
DATABASE_URL = os.environ["DATABASE_URL"]
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))
# Защита входа: MAX_FAILS неверных паролей подряд блокируют аккаунт на LOCK_MIN минут.
MAX_FAILS, LOCK_MIN, IP_LIMIT = 5, 15, 20
REGISTRATION_OPEN = os.environ.get("REGISTRATION_OPEN", "true").lower() == "true"
# Почта (для подтверждения email и восстановления пароля)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@localhost")

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password")  # одинаковое время ответа для несуществующих email
pool = ConnectionPool(DATABASE_URL, open=False, min_size=1, max_size=10, timeout=10)

# База данных: схема создаётся при запуске (повторный запуск безопасен)
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT NOT NULL, at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS login_attempts_ip_at ON login_attempts (ip, at);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_nickname_lower ON users (lower(nickname));
CREATE TABLE IF NOT EXISTS email_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL);
"""


@asynccontextmanager
async def lifespan(app):
    pool.open()
    with pool.connection() as c:
        c.execute(SCHEMA)
        c.execute("DELETE FROM sessions WHERE expires_at < now()")
        c.execute("DELETE FROM login_attempts WHERE at < now() - interval '1 day'")
        c.execute("DELETE FROM email_tokens WHERE expires_at < now()")
    yield
    pool.close()

# Приложение, обработка ошибок, заголовки безопасности
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(PoolTimeout)
@app.exception_handler(psycopg.OperationalError)
async def db_unavailable(request: Request, exc: Exception):
    """База недоступна: отвечаем 503, а не падаем с трассировкой."""
    return JSONResponse({"detail": "Service unavailable"}, status_code=503)


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Добавляет защитные заголовки к каждому ответу и управляет кэшированием."""
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # статика: всегда сверять ETag (правки CSS/JS видны сразу), страницы и API: не кэшировать
    resp.headers["Cache-Control"] = "no-cache" if request.url.path.startswith("/static") else "no-store"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp

# Вспомогательные функции
def sha(token: str) -> str:
    """Хеш токена. В базе хранятся только хеши: утечка БД не раскрывает рабочие токены."""
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def hit(c, key: str, limit: int, minutes: int) -> bool:
    """Ограничитель частоты: True, если действие разрешено (и попытка записана)."""
    row = c.execute("SELECT count(*) FROM login_attempts WHERE ip=%s "
                    "AND at > now() - make_interval(mins => %s)", (key, minutes)).fetchone()
    if row and row[0] >= limit:
        return False
    c.execute("INSERT INTO login_attempts (ip) VALUES (%s)", (key,))
    c.commit()
    return True


def new_token(c, user_id: int, purpose: str, hours: int) -> str:
    """Создаёт одноразовый токен для письма; прежний токен того же назначения аннулируется."""
    c.execute("DELETE FROM email_tokens WHERE user_id=%s AND purpose=%s", (user_id, purpose))
    token = secrets.token_urlsafe(32)
    c.execute("INSERT INTO email_tokens (token_hash, user_id, purpose, expires_at) "
              "VALUES (%s, %s, %s, now() + make_interval(hours => %s))",
              (sha(token), user_id, purpose, hours))
    return token


def send_mail(to: str, subject: str, body: str) -> None:
    """Отправляет письмо по SMTP. Без SMTP_HOST печатает его в консоль (режим разработки)."""
    if not SMTP_HOST:  # режим разработки: письмо печатается в консоль сервера
        print(f"\n[ПОЧТА НЕ НАСТРОЕНА] Кому: {to}\nТема: {subject}\n{body}\n", flush=True)
        return
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = SMTP_FROM, to, subject
    msg.set_content(body)
    try:
        ctx = ssl.create_default_context()
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=15) as srv:
                if SMTP_USER:
                    srv.login(SMTP_USER, SMTP_PASSWORD)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as srv:
                srv.starttls(context=ctx)
                if SMTP_USER:
                    srv.login(SMTP_USER, SMTP_PASSWORD)
                srv.send_message(msg)
    except Exception as exc:  # письмо не должно ронять запрос
        print(f"Ошибка отправки почты: {exc!r}", flush=True)


def check_origin(request: Request):  # защита от CSRF поверх SameSite=Strict
    if request.headers.get("origin") != BASE_URL:
        raise HTTPException(403, "Forbidden")


def current_user(request: Request):
    token = request.cookies.get("sid")
    if not token:
        return None
    with pool.connection() as c:
        return c.execute(
            "SELECT u.id, u.email, u.nickname FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = %s AND s.expires_at > now()", (sha(token),)).fetchone()

# Схемы запросов
class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)  # лимит против DoS на хешировании


@app.post("/api/login")
def login(body: LoginIn, request: Request, response: Response):
    check_origin(request)
    ip = request.client.host if request.client else "unknown"
    email = body.email.lower()
    with pool.connection() as c:
        row = c.execute("SELECT count(*) FROM login_attempts WHERE ip=%s "
                        "AND at > now() - interval '15 minutes'", (ip,)).fetchone()
        recent = row[0] if row else 0
        if recent >= IP_LIMIT:
            raise HTTPException(429, "Too many attempts")
        user = c.execute("SELECT id, password_hash, COALESCE(locked_until > now(), false), email_verified "
                         "FROM users WHERE email=%s", (email,)).fetchone()
        try:
            ph.verify(user[1] if user else DUMMY_HASH, body.password)
            ok = user is not None and not user[2]
        except (VerificationError, InvalidHashError):
            ok = False
        if not ok or user is None:  # второе условие нужно для сужения типа (Pylance)
            c.execute("INSERT INTO login_attempts (ip) VALUES (%s)", (ip,))
            if user and not user[2]:  # пока аккаунт заблокирован, счётчик и срок блокировки не трогаем
                c.execute("UPDATE users SET "
                          "failed_attempts = CASE WHEN failed_attempts + 1 >= %s THEN 0 ELSE failed_attempts + 1 END, "
                          "locked_until = CASE WHEN failed_attempts + 1 >= %s "
                          "THEN now() + make_interval(mins => %s) ELSE locked_until END "
                          "WHERE id=%s", (MAX_FAILS, MAX_FAILS, LOCK_MIN, user[0]))
            c.commit()
            raise HTTPException(401, "Invalid credentials")  # одно сообщение для всех случаев
        if not user[3]:  # пароль верный, но адрес ещё не подтверждён
            raise HTTPException(403, "email_not_verified")
        c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (user[0],))
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions (token_hash, user_id, expires_at) "
                  "VALUES (%s, %s, now() + make_interval(hours => %s))",
                  (sha(token), user[0], SESSION_HOURS))
    response.set_cookie("sid", token, max_age=SESSION_HOURS * 3600, httponly=True,
                        secure=COOKIE_SECURE, samesite="strict", path="/")
    return {"ok": True}

# Вход, выход, профиль
@app.post("/api/logout")
def logout(request: Request, response: Response):
    """Выход: удаляет сессию из БД и cookie."""
    check_origin(request)
    token = request.cookies.get("sid")
    if token:
        with pool.connection() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=%s", (sha(token),))
    response.delete_cookie("sid", path="/")
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return {"email": user[1], "nickname": user[2]}


class RegisterIn(BaseModel):
    nickname: str = Field(pattern=r"^[\w.\-]{3,24}$")  # 3–24 символа: буквы, цифры, . _ -
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=10, max_length=256)

# Регистрация и подтверждение email
@app.post("/api/register")
def register(body: RegisterIn, request: Request, bg: BackgroundTasks):
    check_origin(request)
    if not REGISTRATION_OPEN:
        raise HTTPException(403, "Registration closed")
    email = body.email.lower()
    pw_hash = ph.hash(body.password)  # хешируем всегда: одинаковое время ответа
    with pool.connection() as c:
        if not hit(c, f"reg:{client_ip(request)}", 5, 60):
            raise HTTPException(429, "Too many attempts")
        taken = "SELECT 1 FROM users WHERE lower(nickname) = lower(%s)"
        if c.execute(taken, (body.nickname,)).fetchone():
            raise HTTPException(409, "Nickname taken")
        row = c.execute("INSERT INTO users (email, nickname, password_hash, email_verified) VALUES (%s, %s, %s, false) "
                        "ON CONFLICT DO NOTHING RETURNING id", (email, body.nickname, pw_hash)).fetchone()
        if not row and c.execute(taken, (body.nickname,)).fetchone():  # ник заняли одновременно
            raise HTTPException(409, "Nickname taken")
        if row:
            token = new_token(c, row[0], "verify", 24)
            bg.add_task(send_mail, email, "Подтвердите email — База знаний",
                        f"Чтобы завершить регистрацию, откройте ссылку:\n{BASE_URL}/api/verify?token={token}\n\n"
                        "Ссылка действует 24 часа. Если вы не регистрировались, просто проигнорируйте письмо.")
        else:  # ответ для клиента одинаковый, чтобы не раскрывать, кто уже зарегистрирован
            bg.add_task(send_mail, email, "Аккаунт уже существует — База знаний",
                        f"На этот адрес уже есть аккаунт. Войдите или восстановите пароль: {BASE_URL}/login")
    return {"ok": True}


@app.get("/api/verify")
def verify(token: str = ""):
    with pool.connection() as c:
        row = c.execute("DELETE FROM email_tokens WHERE token_hash=%s AND purpose='verify' "
                        "AND expires_at > now() RETURNING user_id", (sha(token),)).fetchone()
        if row:
            c.execute("UPDATE users SET email_verified=true WHERE id=%s", (row[0],))
    return RedirectResponse("/login#verified" if row else "/login#badlink", status_code=303)

# Восстановление пароля
@app.post("/api/forgot")
def forgot(body: ForgotIn, request: Request, bg: BackgroundTasks):
    check_origin(request)
    email = body.email.lower()
    with pool.connection() as c:
        if not (hit(c, f"forgot:{client_ip(request)}", 5, 15) and hit(c, f"forgot-email:{email}", 3, 60)):
            raise HTTPException(429, "Too many attempts")
        row = c.execute("SELECT id FROM users WHERE email=%s", (email,)).fetchone()
        if row:
            token = new_token(c, row[0], "reset", 1)
            bg.add_task(send_mail, email, "Сброс пароля — База знаний",
                        f"Чтобы задать новый пароль, откройте ссылку (действует 1 час):\n{BASE_URL}/login#reset={token}\n\n"
                        "Если вы не запрашивали сброс, просто проигнорируйте письмо: пароль не изменится.")
    return {"ok": True}  # одинаковый ответ независимо от того, есть ли такой email


@app.post("/api/reset")
def reset_password(body: ResetIn, request: Request):
    check_origin(request)
    pw_hash = ph.hash(body.password)
    with pool.connection() as c:
        if not hit(c, f"reset:{client_ip(request)}", 10, 15):
            raise HTTPException(429, "Too many attempts")
        row = c.execute("DELETE FROM email_tokens WHERE token_hash=%s AND purpose='reset' "
                        "AND expires_at > now() RETURNING user_id", (sha(body.token),)).fetchone()
        if not row:
            raise HTTPException(400, "Invalid or expired token")
        c.execute("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=NULL, "
                  "email_verified=true WHERE id=%s", (pw_hash, row[0]))
        c.execute("DELETE FROM sessions WHERE user_id=%s", (row[0],))  # выйти на всех устройствах
    return {"ok": True}


@app.get("/login")
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(ROOT / "pages" / "login.html")

# Страницы
@app.get("/")
def home(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(ROOT / "pages" / "kb.html")