from app import app, db, User

with app.app_context():
    print("Створення таблиць бази даних...")
    db.create_all()
    print("Таблиці створено.")

    # Перевірка, чи існує користувач 'admin'
    if not User.query.filter_by(username='admin').first():
        print("Створення користувача 'admin'...")
        # Створюємо адміністратора і одразу робимо його активним
        admin_user = User(username='admin', role='admin', is_active=True)
        admin_user.set_password('vet2025')
        db.session.add(admin_user)
        db.session.commit()
        print("Користувача 'admin' створено та активовано.")
    else:
        print("Користувач 'admin' вже існує.")

print("Ініціалізацію бази даних завершено.")