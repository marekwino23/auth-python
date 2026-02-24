from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import db
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserRegisterRequest(BaseModel):
    name: str
    surname:str
    email:str
    password:str
    section:str

class UserLoginRequest(BaseModel):
    email:str
    password:str

# 🔑 Sekretny klucz do podpisywania tokenów JWT
SECRET_KEY = "2f1d3b9a7c5e4d8f0b1a3c6e9d7f2b1c5a3d7e8f9b0c1d2e3f4a5b6c7d8e9f0a"

# 🔒 Algorytm podpisu JWT
ALGORITHM = "HS256"

# ⏳ Czas życia tokenu (w minutach)
ACCESS_TOKEN_EXPIRE_MINUTES = 60    


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

@app.get("/")
def home():
    return "<h1>Form API</h1><p>Użyj /users aby zobaczyć użytkowników</p>"


@app.post("/login", status_code = status.HTTP_200_OK)
def login(user:UserLoginRequest):
    users = db.login_user(user.email, user.password)

    if not users:
        raise HTTPException(status_code=401, detail="Nieprawidłowe dane logowania")
    data = {
        "id": users["id"],        # id użytkownika
        "email": users["email"]   # email użytkownika
    }

    # 4️⃣ Ustawienie daty wygaśnięcia tokenu
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})  # JWT wymaga pola "exp" z datą wygaśnięcia

    # 5️⃣ Generowanie tokenu JWT
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    print(token, "tokeeen")

    # 6️⃣ Zwrócenie tokenu w odpowiedzi
    return {
        "message": "Login successful",
        "user": users,
        "access_token": token,
        "token_type": "bearer"  # standard nazwy tokenu dla Authorization header
    }

@app.post("/register", status_code=status.HTTP_200_OK)
def create_user(user: UserRegisterRequest):
    db.create_user(
        user.name,
        user.surname,
        user.email,
        user.password,  # <- przekazujemy plain password, db.py hashuje
        user.section
    )
    return {"message": "user successfully created"}

