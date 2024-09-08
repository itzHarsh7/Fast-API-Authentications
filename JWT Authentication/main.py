from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import get_password_hash, verify_password, create_access_token, decode_token, create_refresh_token
from models import User
from schemas import UserCreate, UserLogin, UserResponse
from database import SessionLocal, engine, get_db
from datetime import timedelta


ACCESS_COOKIE_NAME= "JWT-ACCESS"
REFRESH_COOKIE_NAME= "JWT-REFRESH"

# Create all tables in the database
from models import Base
Base.metadata.create_all(bind=engine)

app = FastAPI()

# OAuth2PasswordBearer tells FastAPI that the "Authorization" header is expected in the request
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/register/", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the username or email is already registered
    existing_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash the password and create a new user
    hashed_password = get_password_hash(user.password1)
    db_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token/", response_model=dict)
def login_for_access_token(
    response: Response,  # Add Response to the function parameters
    user: UserLogin = Depends(),
    db: Session = Depends(get_db)
):
    # Check if the user exists by username or email
    db_user = db.query(User).filter(
        (User.username == user.username_or_email) | (User.email == user.username_or_email)
    ).first()
    
    # Verify user credentials
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access and refresh tokens
    user_data = {
        "username": db_user.username,  # Standard JWT claim for the subject
        "email": db_user.email,
        "first_name": db_user.first_name,
        "last_name": db_user.last_name
    }
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data=user_data ,expires_delta=access_token_expires
    )
    
    refresh_token_expires = timedelta(hours=5)
    refresh_token = create_refresh_token(
        data=user_data, expires_delta=refresh_token_expires
    )
    
    # Set cookies using the Response object
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        httponly=True,
        max_age=int(access_token_expires.total_seconds())
    )
    
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        max_age=int(refresh_token_expires.total_seconds())
    )
    
    # Return access and refresh tokens in the response body
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=UserResponse)
def read_users_me(request:Request, db: Session = Depends(get_db)):
    payload = decode_token(request.cookies.get(ACCESS_COOKIE_NAME)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    username = payload.get("username")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    db_user = db.query(User).filter(User.username == username).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return db_user


@app.post("/refresh-token/")
async def refresh_token(request: Request, response: Response):  # Add Response parameter
    # Retrieve the refresh token from the cookies
    refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    if not refresh:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not provided")

    # Decode the refresh token
    payload = decode_token(refresh)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Extract the username from the token's payload
    username = payload.get("username")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Create a new access token
    access_token_expires = timedelta(minutes=30)
    new_access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)

    # Create a new refresh token
    refresh_token_expires = timedelta(hours=5)
    new_refresh_token = create_refresh_token(data={"sub": username}, expires_delta=refresh_token_expires)

    # Set cookies for the new access and refresh tokens
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=new_access_token,
        httponly=True,
        max_age=int(access_token_expires.total_seconds())
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=new_refresh_token,
        httponly=True,
        max_age=int(refresh_token_expires.total_seconds())
    )

    # Return the new access token in the response body
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }