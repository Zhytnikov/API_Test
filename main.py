from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.declarative import declarative_base
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import sessionmaker, Session    
from fastapi_limiter.depends import RateLimiter
from datetime import datetime, timedelta, date
from email.mime.multipart import MIMEMultipart
from fastapi_limiter import FastAPILimiter
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from email.mime.text import MIMEText
from typing import List, Optional
from cloudinary import uploader
from jose import JWTError, jwt
import cloudinary
import secrets
import smtplib

from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    sqlalchemy_database_url: str
    secret_key: str
    algorithm: str
    mail_username: str
    mail_password: str
    mail_from: str
    mail_port: int
    mail_server: str
    postgres_db: str  
    postgres_user: str  
    postgres_password: str  
    postgres_port: int  

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# З'єднання з бд
SQLALCHEMY_DATABASE_URL = settings.sqlalchemy_database_url
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Користувач
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    email_verified = Column(Boolean, default=False)  # Поле для підтвердження електронної пошти
    avatar_url = Column(String, nullable=True)  # Поле для URL-адреси аватара
    verification_token = Column(String, nullable=True)  # Поле для токена верифікації електронної пошти

# Контакт
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, index=True)
    phone_number = Column(String)
    birth_date = Column(DateTime)
    additional_data = Column(String, nullable=True)

app = FastAPI()

# Налаштування JWT 
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Підключення до бд
def get_db():
    """
    Function to get a database session.

    :return: SQLAlchemy database session object.
    :rtype: SessionLocal
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Генерація секрету та хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генератор токенів
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Function to create an access token.

    :param data: Data to encode into the token.
    :type data: dict
    :param expires_delta: Expiry time delta, defaults to None.
    :type expires_delta: Optional[timedelta], optional
    :return: Encoded JWT access token.
    :rtype: str
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Авторизація через токен
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Додамо CORSMiddleware до додатка
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Функція для відправлення електронного листа з посиланням для верифікації
def send_verification_email(email: str, verification_token: str):
    from_email = settings.mail_from 
    to_email = email
    subject = "Email Verification"
    message = f"Click the link to verify your email: http://localhost:8000/verify-email/{verification_token}"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    smtp_server = settings.mail_server 
    smtp_port = settings.mail_port 

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(from_email, settings.mail_password)  
        server.send_message(msg)

# Оголошення Pydantic моделей 
class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birth_date: date
    additional_data: str = None

class ContactCreateInput(ContactBase):
    pass

class ContactUpdateInput(ContactBase):
    pass

class ContactResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birth_date: date
    additional_data: str = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class ContactCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birth_date: datetime
    additional_data: Optional[str] = None

class ContactUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    birth_date: Optional[datetime] = None
    additional_data: Optional[str] = None

# Отримання поточного користувача
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Авторизація користувача
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Endpoint to authenticate users and generate access tokens.

    :param form_data: Form data containing username and password.
    :type form_data: OAuth2PasswordRequestForm, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Access token response.
    :rtype: dict
    """
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Зареєструвати нового користувача
@app.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Endpoint to register a new user.

    :param user: User registration data.
    :type user: UserCreate
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Created user object.
    :rtype: User
    """
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already registered")
    hashed_password = pwd_context.hash(user.password)
    verification_token = secrets.token_urlsafe(16)  # Генеруємо токен верифікації
    db_user = User(email=user.email, hashed_password=hashed_password, verification_token=verification_token)
    db.add(db_user)
    db.commit()

    # Відправляємо лист з посиланням для верифікації
    send_verification_email(user.email, verification_token)

    db.refresh(db_user)
    return db_user

# Створення нового контакту
@app.post("/contacts/", response_model=ContactResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=3, minutes=1))])
def create_contact(contact: ContactCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to create a new contact for the current user.

    :param contact: Contact data.
    :type contact: ContactCreate
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Created contact object.
    :rtype: ContactResponse
    """
    db_contact = Contact(**contact.dict(), user_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

# Отримання всіх контактів 
@app.get("/contacts/", response_model=List[ContactResponse])
def read_contacts(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to retrieve contacts for the current user.

    :param skip: Number of records to skip, defaults to 0.
    :type skip: int, optional
    :param limit: Maximum number of records to retrieve, defaults to 10.
    :type limit: int, optional
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: List of contacts belonging to the current user.
    :rtype: List[ContactResponse]
    """
    return db.query(Contact).filter(Contact.user_id == current_user.id).offset(skip).limit(limit).all()

# Отримання одного контакту по ID
@app.get("/contacts/{contact_id}", response_model=ContactResponse)
def read_contact(contact_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to retrieve a contact by its ID for the current user.

    :param contact_id: ID of the contact to retrieve.
    :type contact_id: int
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Contact object.
    :rtype: ContactResponse
    """
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return contact

# Оновлення контакту
@app.put("/contacts/{contact_id}", response_model=ContactResponse)
def update_contact(contact_id: int, contact: ContactUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to update a contact by its ID for the current user.

    :param contact_id: ID of the contact to update.
    :type contact_id: int
    :param contact: Updated contact data.
    :type contact: ContactUpdate
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Updated contact object.
    :rtype: ContactResponse
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    for key, value in contact.dict().items():
        if value is not None:
            setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

# Видалення контакту
@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to delete a contact by its ID for the current user.

    :param contact_id: ID of the contact to delete.
    :type contact_id: int
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Confirmation message.
    :rtype: dict
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return {"message": "Contact deleted successfully"}

# Отримання контактів з наближеними днями народження
@app.get("/contacts/birthday", response_model=List[ContactResponse])
def get_contacts_with_upcoming_birthdays(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to retrieve contacts with upcoming birthdays for the current user.

    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: List of contacts with upcoming birthdays.
    :rtype: List[ContactResponse]
    """
    today = datetime.today()
    next_week = today + timedelta(days=7)
    return db.query(Contact).filter(Contact.user_id == current_user.id, Contact.birth_date >= today, Contact.birth_date <= next_week).all()

# Маршрут для підтвердження електронної пошти
@app.get("/verify-email/{verification_token}")
async def verify_email(verification_token: str, db: Session = Depends(get_db)):
    """
    Endpoint to verify user email using a verification token.

    :param verification_token: Verification token sent to the user.
    :type verification_token: str
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Confirmation message.
    :rtype: dict
    """
    user = db.query(User).filter(User.verification_token == verification_token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")
    user.email_verified = True
    db.commit()
    return {"message": "Email successfully verified"}

# Маршрут для оновлення аватара користувача
@app.post("/users/avatar/")
async def update_avatar(background_tasks: BackgroundTasks, avatar_url: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Endpoint to update user avatar.

    :param background_tasks: Background tasks for updating avatar asynchronously.
    :type background_tasks: BackgroundTasks
    :param avatar_url: URL of the new avatar image.
    :type avatar_url: str
    :param current_user: Current authenticated user.
    :type current_user: User, optional
    :param db: SQLAlchemy database session, defaults to Depends(get_db).
    :type db: Session, optional
    :return: Confirmation message.
    :rtype: dict
    """
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    cloudinary_response = uploader.upload(avatar_url)
    
    # Оновлення URL-адреси аватара для користувача
    user.avatar_url = cloudinary_response.get("secure_url")
    db.commit()
    
    return {"message": "Avatar successfully updated"}