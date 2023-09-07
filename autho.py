from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta  # Added import for datetime
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from database import SessionLocal
from typing import Annotated
from models import Users
from pydantic import BaseModel

router = APIRouter(
    prefix='/autho',
    tags=['autho']
)

SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe4'
ALGORITHM = 'HS256'

# Removed duplicate bcrypt_context and oauth2_bearer definitions
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='autho/token')

class CreateUseRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Removed Annotated and simplified the dependency definition
def get_current_db(db: Session = Depends(get_db)):
    return db

@router.post("/", response_model=Token, status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUseRequest, db: Session = Depends(get_current_db)):
    user = Users(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = create_access_token(user.username, user.id, timedelta(minutes=15))  # Added user.id and expires_delta
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_current_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user.username, user.id, timedelta(minutes=15))  # Added user.id and expires_delta
    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(username: str, password: str, db: Session):
    user = db.query(Users).filter(Users.username == username).first()
    if user and bcrypt_context.verify(password, user.hashed_password):
        return user
    return None

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate usesr.')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')



