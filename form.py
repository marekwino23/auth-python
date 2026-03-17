from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import db
from fastapi import BackgroundTasks
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str

class UserRegisterRequest(BaseModel):
    name: str
    surname:str
    email:str
    password:str
    section:str
    is_verified:bool

class UserLoginRequest(BaseModel):
    email:str
    password:str

class UserChangePassword(BaseModel):
    id:int
    email: str
    oldPassword:str
    newPassword:str    

# 🔑 Sekretny klucz do podpisywania tokenów JWT
SECRET_KEY = "2f1d3b9a7c5e4d8f0b1a3c6e9d7f2b1c5a3d7e8f9b0c1d2e3f4a5b6c7d8e9f0a"

# 🔒 Algorytm podpisu JWT
ALGORITHM = "HS256"

# ⏳ Czas życia tokenu (w minutach)
ACCESS_TOKEN_EXPIRE_MINUTES = 60    


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def confirm_token(token: str):
    try:
        email = serializer.loads(
            token,
            salt="email-confirm",
            max_age=3600  # token ważny 1h
        )
        return email
    except Exception:
        return None

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


@app.get("/verify-email")
async def verify_email(token: str):
    email = confirm_token(token)

    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # oznaczasz usera jako verified w DB

    return {"message": "Email verified"}

@app.patch("/change-password")
async def change_password_endpoint(user: UserChangePassword):
    result = db.change_password(
        id=user.id,
        email=user.email,
        old_password=user.oldPassword,
        new_password=user.newPassword
    )
    if not result:
     return JSONResponse(
        status_code=401,
        content={"message": "Niepoprawne hasło lub użytkownik nie istnieje"}
    )
    return {"message": "Password changed successfully"}

@app.patch("/forgot-password")
async def reset_password_endpoint(user: ResetPasswordRequest):
    result = db.reset_password(
        email=user.email,
        new_password=user.new_password
    )

    if not result:
        return JSONResponse(
            status_code=401,
            content={"message": "Użytkownik o takim emailu nie istnieje"}
        )

    return JSONResponse(
        status_code=200,
        content={"message": "Hasło zostało zmienione pomyślnie"}
    )

@app.post("/register", status_code=status.HTTP_200_OK)
async def create_user(user: UserRegisterRequest, background_tasks: BackgroundTasks):
    db.create_user(
        user.name,
        user.surname,
        user.email,
        user.password,  # <- przekazujemy plain password, db.py hashuje
        user.section,
        False,
    )
    token = db.generate_verification_token(user.email)
    link = f"http://localhost:8000/verify-email?token={token}"

    await db.send_verification_email(user.email, background_tasks)
    return {"message": "user successfully created"}

