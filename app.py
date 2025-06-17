import os
import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# ====================================================================
# 1. Налаштування додатку Flask
# ====================================================================

# Визначаємо абсолютний шлях до кореня проекту
basedir = os.path.abspath(os.path.dirname(__file__))

# Створюємо екземпляр Flask, явно вказуючи папки шаблонів та статичних файлів
app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

# Шлях для збереження завантажених файлів
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads') # Змінено на static/uploads
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Дозволені розширення файлів
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Налаштування конфігурації Flask
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'дуже-секретний-ключ-для-розробки'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'vet25.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ====================================================================
# Допоміжна функція для перевірки розширення файлу
# ====================================================================
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ====================================================================
# 2. Ініціалізація бази даних SQLAlchemy
# ====================================================================

db = SQLAlchemy(app)

# ====================================================================
# 3. Ініціалізація системи авторизації Flask-Login
# ====================================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Перенаправляти на сторінку логіну, якщо користувач не авторизований

# ====================================================================
# 4. Моделі для бази даних
# ====================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False) # Ім'я файлу (з розширенням)
    filepath = db.Column(db.String(255), nullable=False) # Відносний шлях до файлу (наприклад, '2025-06-16/image.jpg')
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    checked_for_trichinella = db.Column(db.Boolean, default=False) # Перевірено на трихінель
    checked_for_anisakids = db.Column(db.Boolean, default=False)   # Перевірено на анізакідів

    user = db.relationship('User', backref=db.backref('photos', lazy=True))

    def __repr__(self):
        return f'<Photo {self.filename} by User {self.user_id}>'

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visit_date = db.Column(db.Date, default=db.func.current_date())
    photo_count = db.Column(db.Integer, default=0) # Кількість фото, залишених за цей візит

    user = db.relationship('User', backref=db.backref('visits', lazy=True))

    # Додаємо унікальний індекс, щоб один користувач мав лише один запис за день
    __table_args__ = (db.UniqueConstraint('user_id', 'visit_date', name='_user_visit_date_uc'),)

    def __repr__(self):
        return f'<Visit User:{self.user_id} Date:{self.visit_date} Photos:{self.photo_count}>'

# ====================================================================
# 5. Функція завантаження користувача для Flask-Login
# ====================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ====================================================================
# 6. Маршрути (URL-адреси) додатку
# ====================================================================

@app.route('/')
@login_required # Тепер головна сторінка також вимагає авторизації
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Успішний вхід!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неправильне ім\'я користувача або пароль.', 'danger')

    # === ДОДАЄМО БЛОК TRY-EXCEPT ТУТ ===
    try:
        return render_template('login.html')
    except Exception as e:
        # Якщо виникла помилка під час відображення шаблону, вивести її у термінал
        print(f"Помилка при відображенні login.html: {e}")
        import traceback
        traceback.print_exc() # Вивести повний traceback у термінал
        flash('Виникла внутрішня помилка сервера під час завантаження сторінки.', 'danger')
        return "Сталася помилка під час завантаження сторінки логіну. Перевірте термінал Flask."

@app.route('/register', methods=['GET', 'POST']) # Додав декоратор для маршруту реєстрації
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Користувач з таким ім\'ям вже існує.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Реєстрація успішна! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви успішно вийшли.', 'info')
    return redirect(url_for('login'))

@app.route('/upload_photo', methods=['GET', 'POST'])
@login_required # Дозволити завантажувати фотографії тільки авторизованим користувачам
def upload_photo():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Файл не знайдено', 'danger')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('Файл не вибрано', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            # Створюємо папку для поточної дати, якщо її немає (у static/uploads)
            today_folder = datetime.date.today().strftime('%Y-%m-%d')
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], today_folder)
            os.makedirs(upload_path, exist_ok=True) # Створити папку, якщо не існує

            # Безпечне ім'я файлу
            filename = secure_filename(file.filename)
            # Зберігаємо файл у папку для поточної дати
            file_full_path = os.path.join(upload_path, filename)
            file.save(file_full_path)

            # Отримуємо значення чекбоксів
            checked_trichinella = 'check_trichinella' in request.form
            checked_anisakids = 'check_anisakids' in request.form

            # Зберігаємо інформацію про фотографію в базу даних
            # filepath зберігає відносний шлях від UPLOAD_FOLDER, щоб потім легко відобразити
            db_filepath = os.path.join(today_folder, filename)
            
            new_photo = Photo(
                user_id=current_user.id,
                filename=filename,
                filepath=db_filepath,
                checked_for_trichinella=checked_trichinella, # Збереження стану чекбоксів
                checked_for_anisakids=checked_anisakids
            )
            db.session.add(new_photo)

            # Оновлюємо кількість фотографій для поточного візиту
            today = datetime.date.today()
            visit = Visit.query.filter_by(user_id=current_user.id, visit_date=today).first()

            if visit:
                visit.photo_count += 1
            else:
                new_visit = Visit(user_id=current_user.id, visit_date=today, photo_count=1)
                db.session.add(new_visit)

            db.session.commit()
            flash(f'Файл {filename} успішно завантажено! Трихінель: {checked_trichinella}, Анізакіди: {checked_anisakids}', 'success')
            return redirect(url_for('upload_photo')) # Залишаємо на сторінці завантаження після успіху
        else:
            flash('Недопустимий тип файлу. Дозволені: png, jpg, jpeg, gif.', 'danger')
            return redirect(request.url)

    return render_template('upload_photo.html') # Відобразити форму завантаження

# ====================================================================
# 7. Запуск додатку
# ====================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Створюємо таблиці в базі даних, якщо їх ще немає
        
        # Перевіряємо, чи існує користувач "testuser" та "admin"
        # Якщо ні, створюємо їх
        if not User.query.filter_by(username='testuser').first():
            test_user = User(username='testuser')
            test_user.set_password('testpassword')
            db.session.add(test_user)
            print("Створено користувача: testuser з паролем: testpassword")

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword')
            db.session.add(admin_user)
            print("Створено адміністратора: admin з паролем: adminpassword")
        
        db.session.commit() # Зберігаємо зміни в базу даних
        
    app.run(debug=True) # debug=True дозволяє автоматичне перезавантаження при змінах