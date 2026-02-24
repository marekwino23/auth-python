import mysql.connector
from passlib.context import CryptContext
from fastapi import FastAPI, HTTPException

# bcrypt do hashowania haseł
pwd_context = CryptContext(
    schemes=["argon2"],  # dokładnie "argon2"
    deprecated="auto"
)

db_config = {
    "host": "mn14.webd.pl",
    "user": "vidad_formy",
    "password": "Formy2026@",
    "database": "vidad_formy"
}

def get_connection():
    return mysql.connector.connect(**db_config)

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Sprawdza czy podane hasło pasuje do zahaszowanego"""
    return pwd_context.verify(plain_password, hashed_password)

def create_user(name: str, surname: str, email: str, password: str, section: str):
    """Tworzy użytkownika i zwraca jego id"""
    hashed = hash_password(password)  # hashowanie hasła
    with get_connection() as conn:
        with conn.cursor(buffered=True) as cursor:
           cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )
    existing_user = cursor.fetchone()

    if existing_user:
                raise HTTPException(
                    status_code=409,   # lepszy kod niż 404
                    detail="Podany adres email już istnieje"
                )

    cursor.execute(
                "INSERT INTO users (name, surname, email, password, section) VALUES (%s, %s, %s, %s, %s)",
                (name, surname, email, hashed, section)
            )
    cursor.fetchone()
    conn.commit()
    return cursor.lastrowid

def login_user(email: str, password: str):
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, email, password FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            if not user:
                    raise HTTPException(status_code=404, detail="Nie ma takiego emaila w bazie danych")
            user_id, email, hashed_password = user
            if not verify_password(password, hashed_password):
                print('Brak')
                return None
            return {"id": user_id, "email": email}


def get_users():
    """Zwraca listę wszystkich użytkowników"""
    with get_connection() as conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, name, surname, email, section FROM users")
            users = cursor.fetchall()
    return users