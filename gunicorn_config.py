# Налаштування для Gunicorn
bind = "0.0.0.0:10000"
workers = 4
accesslog = "-"
errorlog = "-"
preload_app = True

def when_ready(server):
    """
    Ця функція виконується один раз, коли сервер готовий.
    Вона створює таблиці в базі даних та початкового адміна.
    """
    # Імпортуємо наш додаток та моделі
    from app import app, db, User
    from sqlalchemy.exc import IntegrityError

    # Створюємо контекст додатку вручну
    with app.app_context():
        # Створюємо всі таблиці
        db.create_all()

        # Намагаємося створити адміністратора.
        # Використовуємо try-except, щоб уникнути помилки, якщо він вже існує.
        try:
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword')
            db.session.add(admin_user)
            db.session.commit()
            print("Базу даних та початкового адміністратора успішно створено.")
        except IntegrityError:
            # Якщо виникає помилка цілісності, це означає, що адмін вже існує.
            # Ми відкочуємо сесію і просто продовжуємо.
            db.session.rollback()
            print("Адміністратор вже існує. Пропускаємо створення.")
        except Exception as e:
            # Обробляємо будь-які інші несподівані помилки
            db.session.rollback()
            print(f"Сталася несподівана помилка при створенні адміна: {e}")
