from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from main import app, get_db
import requests
import pytest

# Тестовий клієнт для FastAPI
client = TestClient(app)

# Тестового з'єднання з базою даних
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="module")
def setup():
    from main import Base, engine
    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)

# Тест для маршруту /contacts/
def test_get_contacts(setup):
    # Очікувані поля контакту
    expected_fields = ["user_id", "first_name", "last_name", "email", "phone_number", "birth_date", "additional_data"]
    # Виконання GET-запиту 
    response = client.get("/contacts/")
    # Перевірка статусу коду
    assert response.status_code == 200
    # Перевірка типу відповіді
    assert response.headers["content-type"] == "application/json"
    assert isinstance(response.json(), list)
    # Перевірка, що кожен контакт має очікувані поля
    for contact in response.json():
        assert all(field in contact for field in expected_fields)

