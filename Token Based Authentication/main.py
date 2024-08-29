from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
import secrets
from passlib.context import CryptContext
from models import SessionLocal, User, Token
from schemas import UserCreate, TokenResponse, UserLogin



app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token():
    return secrets.token_hex(16)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str, db: Session = Depends(get_db)):
    db_token = db.query(Token).filter(Token.token == token).first()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return db_token.user


@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password1)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully!"}

@app.post("/login/", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter((User.username == user.username_or_email) | (User.email == user.username_or_email)).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    # Create token if first time user login and retrieve token if user already exists
    token = db.query(Token).filter(Token.user_id == db_user.id).first()
    if not token:
        token = Token(token=create_access_token(), user_id=db_user.id)
        db.add(token)
        db.commit()
        db.refresh(token)
    
    return {"token": token.token}

@app.get("/protected-route/")
def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.first_name}, you are authenticated!"}
