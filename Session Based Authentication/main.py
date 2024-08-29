from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Form
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from uuid import uuid4
from sqlalchemy.exc import IntegrityError
from models import User, Session as DBSession, SessionLocal
from schemas import UserCreate, UserLogin, UserResponse, TokenResponse

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory storage for sessions
SESSION_COOKIE_NAME = "session_id"
SESSION_EXPIRE_TIME = 3600  # 1 hour


def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_session(db: Session, user_id: int) -> str:
    session_id = str(uuid4())
    db_session = DBSession(session_id=session_id, user_id=user_id)
    db.add(db_session)
    db.commit()
    return session_id

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    db_session = db.query(DBSession).filter(DBSession.session_id == session_id).first()
    if not db_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )
    user = db.query(User).filter(User.id == db_session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user

@app.post("/register/", response_model=UserResponse)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password1)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
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

@app.post("/login/", response_model=TokenResponse)
async def login(response: Response, user: UserLogin, db: Session = Depends(get_db)):
    db_user = (
        db.query(User)
        .filter(
            (User.username == user.username_or_email)
            | (User.email == user.username_or_email)
        )
        .first()
    )
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    session_id = create_session(db, db_user.id)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=session_id, httponly=True)
    return {"session_id": session_id}

@app.post("/logout/")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        db.query(DBSession).filter(DBSession.session_id == session_id).delete()
        db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"message": "Logged out successfully"}

@app.get("/protected-route/", response_model=UserResponse)
async def protected_route(current_user: User = Depends(get_current_user)):
    return current_user
