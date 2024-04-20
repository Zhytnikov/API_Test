from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import MagicMock
import unittest

from main import register_user, login_for_access_token, get_current_user, create_access_token
from main import User, UserCreate

class TestUsers(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.session = MagicMock(spec=AsyncSession)

    async def test_register_user(self):
        user_data = UserCreate(email="test@example.com", password="password123")
        user = await register_user(user=user_data, db=self.session)
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, user_data.email)

    async def test_register_existing_user(self):
        existing_user = User(email="test@example.com", hashed_password="hashed_password")
        self.session.execute().fetchone.return_value = existing_user
        user_data = UserCreate(email="test@example.com", password="password123")
        with self.assertRaises(ValueError):
            await register_user(user=user_data, db=self.session)

    async def test_login_with_valid_credentials(self):
        user = User(email="test@example.com", hashed_password="hashed_password")
        self.session.execute().fetchone.return_value = user
        form_data = {"username": "test@example.com", "password": "password123"}
        token = await login_for_access_token(form_data=form_data, db=self.session)
        self.assertIn("access_token", token)
        self.assertEqual(token["token_type"], "bearer")

    async def test_login_with_invalid_credentials(self):
        self.session.execute().fetchone.return_value = None
        form_data = {"username": "test@example.com", "password": "password123"}
        with self.assertRaises(ValueError):
            await login_for_access_token(form_data=form_data, db=self.session)

    async def test_get_current_user(self):
        user = User(id=1, email="test@example.com")
        token = create_access_token(data={"sub": user.email})
        db_user = User(email=user.email)
        self.session.execute().fetchone.return_value = db_user
        current_user = await get_current_user(token=token, db=self.session)
        self.assertEqual(current_user.id, user.id)
        self.assertEqual(current_user.email, user.email)

if __name__ == '__main__':
    unittest.main()
