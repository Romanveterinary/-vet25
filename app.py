import os
import datetime
import traceback
import random
import io
from functools import wraps
from sqlalchemy import func

from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw
import openpyxl
import click

# ====================================================================
# 1. Налаштування додатку Flask
# ====================================================================

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'webm'}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'дуже-секретний-ключ-для-розробки'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'vet25.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ====================================================================
# 2. Ініціалізація
# ====================================================================

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ====================================================================
# 4. Моделі для бази даних
# ====================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    photos = db.relationship('Photo', backref='user', lazy='dynamic', cascade="all, delete-orphan")
    enterprises = db.relationship('Enterprise', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Enterprise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'))

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enterprise_id = db.Column(db.Integer, db.ForeignKey('enterprise.id'), nullable=True)
    photo_type = db.Column(db.String(50), nullable=False, default='Не вказано')
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    analyzed_filepath = db.Column(db.String(255), nullable=True)
    checked_for_trichinella = db.Column(db.Boolean, default=False)
    checked_for_anisakids = db.Column(db.Boolean, default=False)
    enterprise = db.relationship('Enterprise', backref=db.backref('photos', lazy=True))
    comments = db.relationship('Comment', backref='photo', lazy='dynamic', cascade="all, delete-orphan")

# ====================================================================
# 5. Допоміжні функції
# ====================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('upload_photo'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user); flash('Успішний вхід!', 'success'); return redirect(url_for('upload_photo'))
        else: flash('Неправильне ім\'я користувача або пароль.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Користувач з таким ім\'ям вже існує.', 'danger'); return redirect(url_for('register'))
        new_user = User(username=username); new_user.set_password(request.form.get('password'))
        db.session.add(new_user); db.session.commit()
        flash('Реєстрація успішна! Тепер ви можете увійти.', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Ви успішно вийшли.', 'info'); return redirect(url_for('login'))

@app.route('/upload_photo', methods=['GET', 'POST'])
@login_required
def upload_photo():
    enterprises = Enterprise.query.filter_by(user_id=current_user.id).order_by(Enterprise.name).all()
    if request.method == 'POST':
        if 'file' not in request.files: flash('Файл не знайдено', 'danger'); return redirect(request.url)
        file, enterprise_id = request.files['file'], request.form.get('enterprise_id')
        photo_type = request.form.get('photo_type')
        if not all([file.filename, enterprise_id, photo_type]):
            flash('Будь ласка, заповніть усі поля.', 'danger'); return render_template('upload_photo.html', enterprises=enterprises)
        if allowed_file(file.filename):
            today_folder = datetime.date.today().strftime('%Y-%m-%d')
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], today_folder)
            os.makedirs(upload_path, exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(upload_path, filename))
            db_filepath = os.path.join(today_folder, filename).replace('\\', '/')
            new_photo = Photo(user_id=current_user.id, filename=filename, filepath=db_filepath, 
                              enterprise_id=enterprise_id, photo_type=photo_type,
                              checked_for_trichinella='check_trichinella' in request.form,
                              checked_for_anisakids='check_anisakids' in request.form)
            db.session.add(new_photo); db.session.commit()
            flash(f'Файл {filename} успішно завантажено!', 'success'); return redirect(url_for('upload_photo'))
        else: flash('Недопустимий тип файлу.', 'danger'); return redirect(request.url)
    return render_template('upload_photo.html', enterprises=enterprises)

@app.route('/my_photos')
@login_required
def my_photos():
    photos = Photo.query.filter_by(user_id=current_user.id).order_by(Photo.upload_date.desc()).all()
    return render_template('my_photos.html', photos=photos)

@app.route('/community_feed')
@login_required
def community_feed():
    all_photos = Photo.query.order_by(Photo.upload_date.desc()).all()
    return render_template('community_feed.html', photos=all_photos)

@app.route('/perform_analysis/<int:photo_id>')
@login_required
def perform_analysis(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    if photo.user.id != current_user.id:
        flash('У вас немає доступу до цього фото.', 'danger'); return redirect(url_for('my_photos'))
    if photo.analyzed_filepath:
        return redirect(url_for('show_analysis', photo_id=photo.id))
    try:
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath.replace('/', os.path.sep))
        if not os.path.exists(original_path):
            flash(f'Помилка: вихідний файл не знайдено.', 'danger'); return redirect(url_for('my_photos'))
        
        analyzed_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'analyzed')
        os.makedirs(analyzed_dir, exist_ok=True)
        filename, ext = os.path.splitext(photo.filename)
        analyzed_filename = f"{filename}_analyzed{ext}"
        analyzed_save_path = os.path.join(analyzed_dir, analyzed_filename)
        with Image.open(original_path) as img:
            img_copy = img.convert("RGB"); draw = ImageDraw.Draw(img_copy)
            width, height = img_copy.size
            for _ in range(random.randint(3, 5)):
                x, y = random.randint(0, width - 50), random.randint(0, height - 50)
                radius = random.randint(10, 25)
                draw.ellipse([x, y, x + radius*2, y + radius*2], outline='red', width=3)
            img_copy.save(analyzed_save_path)
        photo.analyzed_filepath = os.path.join('analyzed', analyzed_filename).replace('\\', '/')
        db.session.commit()
        flash(f'Фото "{photo.filename}" успішно проаналізовано.', 'success')
        return redirect(url_for('show_analysis', photo_id=photo.id))
    except Exception as e:
        print(f"ПОМИЛКА в perform_analysis: {e}"); traceback.print_exc()
        flash('Під час аналізу фото сталася помилка.', 'danger')
        return redirect(url_for('my_photos'))

@app.route('/analysis_result/<int:photo_id>', methods=['GET', 'POST'])
@login_required
def show_analysis(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    if request.method == 'POST':
        comment_text = request.form.get('comment_text')
        if comment_text:
            comment = Comment(text=comment_text, author=current_user, photo=photo)
            db.session.add(comment); db.session.commit()
            flash('Ваш коментар додано.', 'success')
        else: flash('Текст коментаря не може бути порожнім.', 'danger')
        return redirect(url_for('show_analysis', photo_id=photo_id))
    comments = photo.comments.order_by(Comment.timestamp.asc()).all()
    return render_template('analysis_result.html', photo=photo, comments=comments)

@app.route('/my_enterprises', methods=['GET', 'POST'])
@login_required
def my_enterprises():
    if request.method == 'POST':
        name = request.form.get('enterprise_name')
        if name and not Enterprise.query.filter_by(name=name, user_id=current_user.id).first():
            db.session.add(Enterprise(name=name, user_id=current_user.id)); db.session.commit()
            flash(f'Підприємство "{name}" успішно додано.', 'success')
        else: flash('Таке підприємство вже існує у вас або назва порожня.', 'danger')
        return redirect(url_for('my_enterprises'))
    enterprises = Enterprise.query.filter_by(user_id=current_user.id).order_by(Enterprise.name).all()
    return render_template('my_enterprises.html', enterprises=enterprises)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    all_photos = Photo.query.order_by(Photo.upload_date.desc()).all()
    all_users = User.query.filter(User.is_admin == False).order_by(User.registration_date.desc()).all()
    return render_template('admin_dashboard.html', photos=all_photos, users=all_users)

@app.route('/admin/reports')
@login_required
@admin_required
def reports():
    seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    users = User.query.filter(User.is_admin == False).all()
    report_data = []
    for user in users:
        photos_query = db.session.query(Enterprise.name, func.count(Photo.id)).join(Enterprise).filter(Photo.user_id == user.id, Photo.upload_date >= seven_days_ago).group_by(Enterprise.name).all()
        comments_count = user.comments.filter(Comment.timestamp >= seven_days_ago).count()
        report_data.append({
            'user': user, 'photos_total': sum(c for _, c in photos_query),
            'photos_by_enterprise': dict(photos_query), 'comments_total': comments_count
        })
    return render_template('reports.html', report_data=report_data)

@app.route('/admin/download_excel_report')
@login_required
@admin_required
def download_excel_report():
    try:
        seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        users = User.query.filter(User.is_admin == False).all()
        workbook = openpyxl.Workbook(); sheet = workbook.active
        sheet.title = "Тижневий звіт"
        sheet.append(["Користувач", "Всього фото", "Всього коментарів", "Деталізація по підприємствах"])
        for user in users:
            photos_query = db.session.query(Enterprise.name, func.count(Photo.id)).join(Enterprise).filter(Photo.user_id == user.id, Photo.upload_date >= seven_days_ago).group_by(Enterprise.name).all()
            comments_count = user.comments.filter(Comment.timestamp >= seven_days_ago).count()
            enterprises_str = ", ".join([f"{name}: {count}" for name, count in photos_query]) if photos_query else "Немає"
            sheet.append([user.username, sum(c for _, c in photos_query), comments_count, enterprises_str])
        virtual_workbook = io.BytesIO()
        workbook.save(virtual_workbook); virtual_workbook.seek(0)
        return send_file(virtual_workbook, as_attachment=True, download_name=f'weekly_report_{datetime.date.today()}.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        print(f"Помилка при генерації Excel-звіту: {e}"); traceback.print_exc()
        flash('Не вдалося згенерувати звіт.', 'danger'); return redirect(url_for('reports'))

@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    photos = user.photos.order_by(Photo.upload_date.desc()).all()
    comments = user.comments.order_by(Comment.timestamp.desc()).all()
    return render_template('user_details.html', user=user, photos=photos, comments=comments)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    if new_password and len(new_password) >= 6:
        user.set_password(new_password); db.session.commit()
        flash(f'Пароль для користувача "{user.username}" було успішно скинуто.', 'success')
    else: flash('Новий пароль має бути не менше 6 символів.', 'danger')
    return redirect(url_for('user_details', user_id=user.id))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.is_admin:
        flash('Неможливо видалити іншого адміністратора.', 'danger'); return redirect(url_for('admin_dashboard'))
    try:
        for photo in user_to_delete.photos:
             if photo.filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath))
             if photo.analyzed_filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath))
        db.session.delete(user_to_delete); db.session.commit()
        flash(f'Користувача "{user_to_delete.username}" та всі його дані було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні користувача: {e}"); traceback.print_exc()
        flash('Під час видалення користувача сталася помилка.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
@login_required
@admin_required
def delete_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    try:
        if photo.filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath))
        if photo.analyzed_filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath))
        db.session.delete(photo); db.session.commit()
        flash(f'Фото "{photo.filename}" та всі пов\'язані коментарі було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні фото: {e}"); traceback.print_exc()
        flash('Під час видалення фото сталася помилка.', 'danger')
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
@admin_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    try:
        db.session.delete(comment); db.session.commit()
        flash('Коментар було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні коментаря: {e}"); traceback.print_exc()
        flash('Під час видалення коментаря сталася помилка.', 'danger')
    return redirect(request.referrer or url_for('index'))

# ====================================================================
# 7. Запуск додатку
# ====================================================================

@app.cli.command("init-db")
def init_db_command():
    """Створює таблиці бази даних та початкового адміна."""
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('adminpassword')
        db.session.add(admin_user)
        db.session.commit()
        print("Базу даних та адміністратора створено.")
    else:
        print("Адміністратор вже існує.")

if __name__ == '__main__':
    app.run(debug=True)
