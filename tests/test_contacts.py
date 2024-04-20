from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import MagicMock
import unittest

from main import create_contact, update_contact, delete_contact, read_contacts, read_contact, get_contacts_with_upcoming_birthdays
from main import ContactCreate, ContactUpdate
from main import app, User, Contact

class TestContacts(unittest.IsolatedAsyncioTestCase):  

    async def asyncSetUp(self):
        self.session = MagicMock(spec=AsyncSession)
        self.user = User(id=1, email="test@example.com")

    async def test_create_contact(self):
        contact_data = ContactCreate(first_name="John", last_name="Doe", email="john@example.com",
                                     phone_number="1234567890", birth_date="1990-01-01")
        contact = await create_contact(contact=contact_data, current_user=self.user, db=self.session)
        self.assertIsInstance(contact, Contact)
        self.assertEqual(contact.first_name, contact_data.first_name)

    async def test_update_contact(self):
        contact_id = 1
        updated_data = ContactUpdate(first_name="Jane")
        contact = Contact(id=contact_id, first_name="John", last_name="Doe", email="john@example.com",
                          phone_number="1234567890", birth_date="1990-01-01")
        self.session.execute().fetchone.return_value = contact
        updated_contact = await update_contact(contact_id=contact_id, contact=updated_data, current_user=self.user, db=self.session)
        self.assertEqual(updated_contact.first_name, updated_data.first_name)

    async def test_delete_contact(self):
        contact_id = 1
        contact = Contact(id=contact_id, first_name="John", last_name="Doe", email="john@example.com",
                          phone_number="1234567890", birth_date="1990-01-01")
        self.session.execute().fetchone.return_value = contact
        deleted_contact = await delete_contact(contact_id=contact_id, current_user=self.user, db=self.session)
        self.assertEqual(deleted_contact.id, contact_id)

    async def test_get_contacts(self):
        contacts = [Contact(id=1, first_name="John", last_name="Doe", email="john@example.com",
                            phone_number="1234567890", birth_date="1990-01-01")]
        self.session.execute().fetchall.return_value = contacts
        fetched_contacts = await read_contacts(skip=0, limit=10, current_user=self.user, db=self.session)
        self.assertEqual(len(fetched_contacts), len(contacts))
        self.assertEqual(fetched_contacts[0].first_name, contacts[0].first_name)

    async def test_read_contact(self):
        contact_id = 1
        contact = Contact(id=contact_id, first_name="John", last_name="Doe", email="john@example.com",
                        phone_number="1234567890", birth_date="1990-01-01")
        self.session.execute().fetchone.return_value = contact
        fetched_contact = await read_contact(contact_id=contact_id, current_user=self.user, db=self.session)
        self.assertEqual(fetched_contact.first_name, contact.first_name)


    async def test_get_contacts_with_upcoming_birthdays(self):
        contacts = [Contact(id=1, first_name="John", last_name="Doe", email="john@example.com",
                            phone_number="1234567890", birth_date="1990-01-01")]
        self.session.execute().fetchall.return_value = contacts
        fetched_contacts = await get_contacts_with_upcoming_birthdays(current_user=self.user, db=self.session)
        self.assertEqual(len(fetched_contacts), len(contacts))
        self.assertEqual(fetched_contacts[0].first_name, contacts[0].first_name)

if __name__ == '__main__':
    unittest.main()
