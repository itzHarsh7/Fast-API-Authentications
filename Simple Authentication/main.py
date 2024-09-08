# main.py
from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from schemas import *
from models import User, SessionLocal

app = FastAPI()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password1)
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    )
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"message": "User registered successfully!"}
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

@app.post("/login/")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = (
        db.query(User)
        .filter(
            (User.username == user.username_or_email)
            | (User.email == user.username_or_email)
        )
        .first()
    )
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return {"message": "Login successful!"}

@app.post("/logout/")
def logout():
    return {"message": "Logout successful!"}

