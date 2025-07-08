# create_tables.py
from app import app, db

# Створюємо контекст додатку
with app.app_context():
    # Створюємо всі таблиці бази даних
    db.create_all()

print("Database tables created successfully.")