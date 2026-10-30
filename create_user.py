import getpass, os, re, sys
import psycopg
from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv()
email = input("Email: ").strip().lower()
nick = input("Никнейм (3–24 символа, необязательно): ").strip() or None
if nick and not re.fullmatch(r"[\w.\-]{3,24}", nick):
    sys.exit("Недопустимый никнейм")
pw = getpass.getpass("Пароль (мин. 10 символов): ")
if len(pw) < 10 or pw != getpass.getpass("Повторите пароль: "):
    sys.exit("Пароль слишком короткий или не совпал")
with psycopg.connect(os.environ["DATABASE_URL"]) as c:
    c.execute("INSERT INTO users (email, nickname, password_hash) VALUES (%s, %s, %s)",
              (email, nick, PasswordHasher().hash(pw)))
print("Готово")