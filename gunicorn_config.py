# Налаштування для Gunicorn
bind = "0.0.0.0:10000"
workers = 4
accesslog = "-"
errorlog = "-"
preload_app = True

def when_ready(server):
    """
    Ця функція виконується один раз, коли сервер готовий.
    Вона створює таблиці в базі даних.
    """
    # Імпортуємо наш додаток та моделі
    from app import app, db, User

    # Створюємо контекст додатку вручну
    with app.app_context():
        # Створюємо всі таблиці
        db.create_all()

        # Створюємо адміністратора, якщо його ще немає
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword')
            db.session.add(admin_user)
            db.session.commit()
            print("Базу даних та початкового адміністратора створено.")
        else:
            print("Адміністратор вже існує.")

