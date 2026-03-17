import mysql.connector
import os
from itsdangerous import URLSafeTimedSerializer
from fastapi import BackgroundTasks, HTTPException
from fastapi_mail import FastMail, MessageSchema
from passlib.context import CryptContext
from config import conf
from dotenv import load_dotenv
load_dotenv()

key = os.getenv("SECRET_KEY")
serializer = URLSafeTimedSerializer(key)  # unikalny klucz

# bcrypt do hashowania haseł
pwd_context = CryptContext(
    schemes=["argon2"],  # dokładnie "argon2"
    deprecated="auto"
)

db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME")
}

def get_connection():
    return mysql.connector.connect(**db_config)

def hash_password(password: str):
    return pwd_context.hash(password)

def generate_verification_token(email: str):
    return serializer.dumps(email, salt="email-confirm")

async def send_verification_email(email: str, background_tasks: BackgroundTasks):
    token = serializer.dumps(email, salt="email-confirm")
    link = f"http://localhost:8000/verify-email?token={token}"
    message = MessageSchema(
        subject="Weryfikacja adresu email",
        recipients=[email],
        body=f"Witaj! Kliknij w link aby potwierdzić adres email: {link}",
        subtype="plain"
    )
    fm = FastMail(conf)
    background_tasks.add_task(fm.send_message, message)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Sprawdza czy podane hasło pasuje do zahaszowanego"""
    return pwd_context.verify(plain_password, hashed_password)

def create_user(name: str, surname: str, email: str, password: str, section: str, is_verified: bool):
    conn = get_connection()

    if not conn.is_connected():
        conn.reconnect()

    cursor = conn.cursor(buffered=True)

    try:
        cursor.execute(
            "SELECT id FROM users WHERE email = %s",
            (email,)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="Podany adres email już istnieje"
            )

        hashed = hash_password(password)

        cursor.execute(
            "INSERT INTO users (name, surname, email, password, section, is_verified) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, surname, email, hashed, section, False)
        )

        conn.commit()
        return cursor.lastrowid

    finally:
        cursor.close()
        conn.close()

def login_user(email: str, password: str):
    conn = get_connection()

    if not conn.is_connected():
        conn.reconnect()

    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT id, email, password FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Nie ma takiego emaila w bazie danych")

        user_id, email, hashed_password = user

        if not verify_password(password, hashed_password):
            return None

        return {"id": user_id, "email": email}

    finally:
        cursor.close()
        conn.close()


def get_users():
    """Zwraca listę wszystkich użytkowników"""
    with get_connection() as conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, name, surname, email, section FROM users")
            users = cursor.fetchall()
    return users