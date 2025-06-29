import os
import datetime
import traceback
import random
import io
import uuid
from functools import wraps
from urllib.parse import urlparse

from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw
import openpyxl
from markupsafe import Markup
from google.cloud import storage

# ====================================================================
# 1. Налаштування додатку Flask
# ====================================================================

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'дуже-секретний-ключ-для-розробки'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'vet25.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ====================================================================
# 2. Налаштування Google Cloud Storage
# ====================================================================

try:
    if os.path.exists('config/gcs_key.json'):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "config/gcs_key.json"
    
    storage_client = storage.Client()
    BUCKET_NAME = "vet25-photos-1975" # ВАШЕ ІМ'Я BUCKET
    bucket = storage_client.bucket(BUCKET_NAME)
    print("Клієнт Google Cloud Storage успішно ініціалізовано.")
except Exception as e:
    print(f"ПОМИЛКА ініціалізації Google Cloud Storage: {e}")
    storage_client = None
    bucket = None

# ====================================================================
# 3. Ініціалізація та моделі даних
# ====================================================================

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def nl2br(value):
    return Markup(value.replace('\n', '<br>\n'))
app.jinja_env.filters['nl2br'] = nl2br

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    registration_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    role = db.Column(db.String(20), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    photos = db.relationship('Photo', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    enterprises = db.relationship('Enterprise', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self): return self.role == 'admin'
    @property
    def is_manager(self): return self.role in ['manager', 'admin']

class Enterprise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.UTC))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=True)
    public_inquiry_id = db.Column(db.Integer, db.ForeignKey('public_inquiry.id'), nullable=True)
    
    photo = db.relationship('Photo', backref=db.backref('comments', lazy='dynamic', cascade="all, delete-orphan"))
    public_inquiry = db.relationship('PublicInquiry', backref=db.backref('comments', lazy='dynamic', cascade="all, delete-orphan"))

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enterprise_id = db.Column(db.Integer, db.ForeignKey('enterprise.id'), nullable=True)
    photo_type = db.Column(db.String(50), nullable=False, default='Не вказано')
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(512), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    analyzed_filepath = db.Column(db.String(512), nullable=True)
    checked_for_trichinella = db.Column(db.Boolean, default=False)
    checked_for_anisakids = db.Column(db.Boolean, default=False)
    enterprise = db.relationship('Enterprise', backref=db.backref('photos', lazy=True))

class PublicInquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitter_name = db.Column(db.String(150), nullable=False)
    submitter_phone = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(255), nullable=False)
    circumstances = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(255), nullable=False)
    photo_filepath = db.Column(db.String(512), nullable=False)
    submission_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    status = db.Column(db.String(50), default='Новий')
    admin_comment = db.Column(db.Text, nullable=True)
    access_token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

# НОВА МОДЕЛЬ для логів чату
class ChatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.datetime.now(datetime.UTC))
    user_prompt = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=True)
    
    # Встановлюємо зв'язок з моделлю User
    user = db.relationship('User', backref=db.backref('chat_logs', lazy='dynamic'))

# ====================================================================
# 4. Допоміжні функції для роботи з GCS
# ====================================================================

def upload_to_gcs(file_stream, content_type, folder, original_filename):
    if not bucket: raise Exception("GCS bucket не ініціалізовано.")
    filename = f"{uuid.uuid4()}-{secure_filename(original_filename)}"
    gcs_path = f"{folder}/{filename}"
    blob = bucket.blob(gcs_path)
    blob.upload_from_file(file_stream, content_type=content_type)
    blob.make_public()
    return blob.public_url

def delete_from_gcs(public_url):
    if not bucket or not public_url: return
    try:
        parsed_url = urlparse(public_url)
        gcs_path = parsed_url.path.lstrip('/')
        blob_name = gcs_path.replace(f"{BUCKET_NAME}/", "", 1)
        blob = bucket.blob(blob_name)
        if blob.exists():
            blob.delete()
    except Exception as e:
        print(f"Помилка видалення файлу {public_url} з GCS: {e}")

# ====================================================================
# 5. Декоратори та завантажувач користувача
# ====================================================================
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_manager:
            flash('Для доступу до цієї сторінки потрібні права керівника або адміністратора.', 'danger'); return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Для доступу до цієї сторінки потрібні права адміністратора.', 'danger'); return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
    
# ====================================================================
# 6. Маршрути
# ====================================================================

# Всі ваші маршрути залишаються тут без змін на даному етапі.
# Ми оновимо їх пізніше, після того як налаштуємо бекенд чат-бота.
# Я просто залишу тут декілька для структури.

@app.route('/')
def index(): return render_template('index.html')

@app.route('/upload_photo', methods=['GET', 'POST'])
@login_required
def upload_photo():
    enterprises = Enterprise.query.filter_by(user_id=current_user.id).order_by(Enterprise.name).all()
    if request.method == 'POST':
        file = request.files.get('file')
        enterprise_id, photo_type = request.form.get('enterprise_id'), request.form.get('photo_type')
        if not all([file, file.filename, enterprise_id, photo_type]):
            flash('Будь ласка, заповніть усі поля та виберіть файл.', 'danger')
            return render_template('upload_photo.html', enterprises=enterprises)
        
        if allowed_file(file.filename):
            try:
                today_folder = datetime.date.today().strftime('%Y-%m-%d')
                upload_folder_path = f"user_uploads/{current_user.id}/{today_folder}"
                public_url = upload_to_gcs(file.stream, file.content_type, upload_folder_path, file.filename)
                
                new_photo = Photo(user_id=current_user.id, filename=secure_filename(file.filename), filepath=public_url, enterprise_id=enterprise_id, photo_type=photo_type, checked_for_trichinella='check_trichinella' in request.form, checked_for_anisakids='check_anisakids' in request.form)
                db.session.add(new_photo); db.session.commit()
                flash(f'Файл {secure_filename(file.filename)} успішно завантажено!', 'success')
                return redirect(url_for('upload_photo'))
            except Exception as e:
                flash(f'Під час завантаження файлу сталася помилка: {e}', 'danger'); return redirect(request.url)
        else:
            flash('Недопустимий тип файлу.', 'danger'); return redirect(request.url)
    return render_template('upload_photo.html', enterprises=enterprises)

@app.route('/my_photos')
@login_required
def my_photos():
    photos = Photo.query.filter_by(user_id=current_user.id).order_by(Photo.upload_date.desc()).all()
    return render_template('my_photos.html', photos=photos)
    
# (тут мають бути всі інші ваші маршрути: /community_feed, /login, /register, /admin/dashboard і т.д.)
# Просто переконайтеся, що вони тут є, їхній код поки що не змінюється.

# ====================================================================
# 7. Створення бази даних та початкових користувачів
# ====================================================================

with app.app_context():
    db.create_all()

@app.cli.command("init-db")
def init_db_command():
    """Створює/очищує базу даних та створює початкових користувачів."""
    db.drop_all()
    db.create_all()
    
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin', is_active=True)
        admin_user.set_password('adminpassword'); db.session.add(admin_user)
        print("Створено адміністратора.")

    if not User.query.filter_by(username='manager').first():
        manager_user = User(username='manager', role='manager', is_active=True)
        manager_user.set_password('managerpass'); db.session.add(manager_user)
        print("Створено керівника.")
        
    db.session.commit()
    print("Ініціалізовано базу даних з новою таблицею ChatLog.")

if __name__ == '__main__':
    app.run(debug=True)