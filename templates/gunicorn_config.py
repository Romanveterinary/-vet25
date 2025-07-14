import subprocess

# Виконуємо команду для ініціалізації бази даних
# Це буде виконано лише один раз при першому запуску після деплою
try:
    print("Attempting to initialize the database...")
    subprocess.run(["flask", "init-db"], check=True)
    print("Database initialization command executed.")
except Exception as e:
    print(f"Database initialization failed or already done: {e}")

# Стандартні налаштування Gunicorn
bind = "0.0.0.0:10000"
workers = 3
