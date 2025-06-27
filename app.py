import os
import datetime
import traceback
import random
import io
import uuid
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
from markupsafe import Markup

# ====================================================================
# 1. Налаштування додатку Flask
# ====================================================================

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'дуже-секретний-ключ-для-розробки'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'vet25.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ====================================================================
# 2. Ініціалізація
# ====================================================================

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ====================================================================
# 3. Кастомні фільтри для шаблонів
# ====================================================================
def nl2br(value):
    """Перетворює символи нового рядка у HTML-теги <br>."""
    return Markup(value.replace('\n', '<br>\n'))

app.jinja_env.filters['nl2br'] = nl2br

# ====================================================================
# 4. Моделі для бази даних
# ====================================================================

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
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_manager(self):
        return self.role in ['manager', 'admin']

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
    filepath = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    analyzed_filepath = db.Column(db.String(255), nullable=True)
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
    photo_filepath = db.Column(db.String(255), nullable=False)
    submission_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    status = db.Column(db.String(50), default='Новий')
    admin_comment = db.Column(db.Text, nullable=True)
    access_token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

with app.app_context():
    db.create_all()

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
@app.route('/')
def index(): return render_template('index.html')

@app.route('/safety-check', methods=['GET', 'POST'])
def safety_check():
    if request.method == 'POST':
        submitter_name = request.form.get('submitter_name')
        submitter_phone = request.form.get('submitter_phone')
        location = request.form.get('location')
        circumstances = request.form.get('circumstances')
        if 'photo' not in request.files:
            flash('Фото є обов\'язковим.', 'danger'); return redirect(request.url)
        photo_file = request.files['photo']
        if not all([submitter_name, location, circumstances, photo_file.filename]):
            flash('Будь ласка, заповніть усі обов\'язкові поля та додайте фото.', 'danger'); return redirect(request.url)
        if allowed_file(photo_file.filename):
            today_folder = datetime.date.today().strftime('%Y-%m-%d')
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'public_inquiries', today_folder)
            os.makedirs(upload_path, exist_ok=True)
            filename = secure_filename(photo_file.filename)
            photo_file.save(os.path.join(upload_path, filename))
            db_filepath = os.path.join('public_inquiries', today_folder, filename).replace('\\', '/')
            new_inquiry = PublicInquiry(
                submitter_name=submitter_name,
                submitter_phone=submitter_phone,
                location=location,
                circumstances=circumstances,
                photo_filename=filename,
                photo_filepath=db_filepath
            )
            db.session.add(new_inquiry)
            db.session.commit()
            flash('Ваше звернення успішно відправлено! Будь ласка, збережіть посилання для перевірки статусу.', 'success')
            return redirect(url_for('submission_success', token=new_inquiry.access_token))
    return render_template('safety_check.html')

@app.route('/submission-success/<token>')
def submission_success(token):
    return render_template('submission_success.html', token=token)

@app.route('/inquiry/<token>')
def view_inquiry(token):
    inquiry = PublicInquiry.query.filter_by(access_token=token).first_or_404()
    comments = inquiry.comments.order_by(Comment.timestamp.asc()).all()
    return render_template('view_inquiry.html', inquiry=inquiry, comments=comments)

@app.route('/complaint-guide')
def complaint_guide(): return render_template('complaint_guide.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('upload_photo'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            if not user.is_active:
                flash('Ваш акаунт ще не схвалено адміністратором.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            flash('Успішний вхід!', 'success')
            return redirect(url_for('upload_photo'))
        else:
            flash('Неправильне ім\'я користувача або пароль.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Користувач з таким ім\'ям вже існує.', 'danger'); return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(request.form.get('password'))
        db.session.add(new_user); db.session.commit()
        flash('Реєстрація успішна! Ваш запит надіслано адміністратору на схвалення.', 'info')
        return redirect(url_for('login'))
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
        file, enterprise_id = request.files['file'], request.form.get('enterprise_id'); photo_type = request.form.get('photo_type')
        if not all([file.filename, enterprise_id, photo_type]):
            flash('Будь ласка, заповніть усі поля.', 'danger'); return render_template('upload_photo.html', enterprises=enterprises)
        if allowed_file(file.filename):
            today_folder = datetime.date.today().strftime('%Y-%m-%d'); upload_path = os.path.join(app.config['UPLOAD_FOLDER'], today_folder)
            os.makedirs(upload_path, exist_ok=True); filename = secure_filename(file.filename)
            file.save(os.path.join(upload_path, filename)); db_filepath = os.path.join(today_folder, filename).replace('\\', '/')
            new_photo = Photo(user_id=current_user.id, filename=filename, filepath=db_filepath, enterprise_id=enterprise_id, photo_type=photo_type, checked_for_trichinella='check_trichinella' in request.form, checked_for_anisakids='check_anisakids' in request.form)
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
    photos_from_users = Photo.query.all(); inquiries_from_public = PublicInquiry.query.all()
    feed_items = []
    for photo in photos_from_users:
        feed_items.append({"post_type": "photo", "post_obj": photo, "display_date": photo.upload_date, "display_image": photo.filepath, "display_author": photo.user.username, "comment_count": photo.comments.count()})
    for inquiry in inquiries_from_public:
        feed_items.append({"post_type": "inquiry", "post_obj": inquiry, "display_date": inquiry.submission_date, "display_image": inquiry.photo_filepath, "display_author": f"Звернення від {inquiry.submitter_name}", "comment_count": inquiry.comments.count()})
    sorted_feed = sorted(feed_items, key=lambda x: x['display_date'], reverse=True)
    return render_template('community_feed.html', feed_items=sorted_feed)

@app.route('/perform_analysis/<int:photo_id>')
@login_required
def perform_analysis(photo_id):
    photo = db.session.get(Photo, photo_id)
    if not photo or photo.user.id != current_user.id:
        flash('У вас немає доступу до цього фото.', 'danger'); return redirect(url_for('my_photos'))
    if photo.analyzed_filepath:
        return redirect(url_for('view_post', post_type='photo', post_id=photo.id))
    try:
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath.replace('/', os.path.sep))
        if not os.path.exists(original_path):
            flash(f'Помилка: вихідний файл не знайдено.', 'danger'); return redirect(url_for('my_photos'))
        analyzed_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'analyzed'); os.makedirs(analyzed_dir, exist_ok=True)
        filename, ext = os.path.splitext(photo.filename); analyzed_filename = f"{filename}_analyzed{ext}"
        analyzed_save_path = os.path.join(analyzed_dir, analyzed_filename)
        with Image.open(original_path) as img:
            img_copy = img.convert("RGB"); draw = ImageDraw.Draw(img_copy)
            width, height = img_copy.size
            for _ in range(random.randint(3, 5)):
                x, y = random.randint(0, width - 50), random.randint(0, height - 50)
                radius = random.randint(10, 25)
                draw.ellipse([x, y, x + radius*2, y + radius*2], outline='red', width=3)
            img_copy.save(analyzed_save_path)
        photo.analyzed_filepath = os.path.join('analyzed', analyzed_filename).replace('\\', '/'); db.session.commit()
        flash(f'Фото "{photo.filename}" успішно проаналізовано.', 'success')
        return redirect(url_for('view_post', post_type='photo', post_id=photo.id))
    except Exception as e:
        print(f"ПОМИЛКА в perform_analysis: {e}"); traceback.print_exc()
        flash('Під час аналізу фото сталася помилка.', 'danger'); return redirect(url_for('my_photos'))

@app.route('/post/<string:post_type>/<int:post_id>', methods=['GET', 'POST'])
@login_required
def view_post(post_type, post_id):
    post = None; comments = []
    if post_type == 'photo':
        post = db.session.get(Photo, post_id)
    elif post_type == 'inquiry':
        post = db.session.get(PublicInquiry, post_id)
    if not post: return "Запис не знайдено", 404
    if request.method == 'POST':
        comment_text = request.form.get('comment_text')
        if comment_text:
            new_comment = Comment(text=comment_text, author=current_user)
            if post_type == 'photo': new_comment.photo_id = post_id
            elif post_type == 'inquiry': new_comment.public_inquiry_id = post_id
            db.session.add(new_comment); db.session.commit()
            flash('Ваш коментар додано.', 'success')
        else: flash('Текст коментаря не може бути порожнім.', 'danger')
        return redirect(url_for('view_post', post_type=post_type, post_id=post_id))
    comments = post.comments.order_by(Comment.timestamp.asc()).all()
    return render_template('view_post.html', post=post, post_type=post_type, comments=comments)
    
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
@manager_required
def admin_dashboard():
    all_photos = Photo.query.order_by(Photo.upload_date.desc()).all()
    pending_users = User.query.filter_by(is_active=False).order_by(User.registration_date.desc()).all()
    active_users = User.query.filter(User.role != 'admin', User.is_active == True).order_by(User.registration_date.desc()).all()
    all_inquiries = PublicInquiry.query.order_by(PublicInquiry.submission_date.desc()).all()
    return render_template('admin_dashboard.html', photos=all_photos, active_users=active_users, pending_users=pending_users, inquiries=all_inquiries)

@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    user = db.session.get(User, user_id)
    if user and not user.is_active:
        user.is_active = True
        db.session.commit()
        flash(f'Користувача "{user.username}" було успішно активовано.', 'success')
    else:
        flash('Користувача не знайдено або він вже активований.', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reports')
@login_required
@manager_required
def reports():
    seven_days_ago = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=7)
    activity_log = []
    photos = Photo.query.filter(Photo.upload_date >= seven_days_ago).all()
    for photo in photos:
        activity_log.append({
            'date': photo.upload_date,
            'user': photo.user,
            'type': 'Завантажено фото',
            'details': photo.filename
        })
    comments = Comment.query.filter(Comment.timestamp >= seven_days_ago).all()
    for comment in comments:
        activity_log.append({
            'date': comment.timestamp,
            'user': comment.author,
            'type': 'Залишено коментар',
            'details': f'"{comment.text[:30]}..."'
        })
    sorted_log = sorted(activity_log, key=lambda x: x['date'], reverse=True)
    return render_template('reports.html', activity_log=sorted_log)

@app.route('/admin/download_excel_report')
@login_required
@manager_required
def download_excel_report():
    try:
        seven_days_ago = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=7)
        activity_log = []
        photos = Photo.query.filter(Photo.upload_date >= seven_days_ago).all()
        for photo in photos:
            activity_log.append({
                'date': photo.upload_date,
                'user_name': photo.user.username,
                'type': 'Завантажено фото',
                'details': photo.filename
            })
        comments = Comment.query.filter(Comment.timestamp >= seven_days_ago).all()
        for comment in comments:
            activity_log.append({
                'date': comment.timestamp,
                'user_name': comment.author.username,
                'type': 'Залишено коментар',
                'details': comment.text
            })
        sorted_log = sorted(activity_log, key=lambda x: x['date'], reverse=True)
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.title = "Журнал Активності"
        sheet.append(["Дата і час", "Користувач", "Тип активності", "Деталі"])
        for item in sorted_log:
            sheet.append([
                item['date'].strftime('%Y-%m-%d %H:%M:%S'),
                item['user_name'],
                item['type'],
                item['details']
            ])
        virtual_workbook = io.BytesIO()
        workbook.save(virtual_workbook)
        virtual_workbook.seek(0)
        return send_file(
            virtual_workbook,
            as_attachment=True,
            download_name=f'activity_log_{datetime.date.today()}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        print(f"Помилка при генерації Excel-звіту: {e}"); traceback.print_exc()
        flash('Не вдалося згенерувати звіт.', 'danger'); return redirect(url_for('reports'))

@app.route('/admin/user/<int:user_id>')
@login_required
@manager_required
def user_details(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('Користувача не знайдено.', 'danger'); return redirect(url_for('admin_dashboard'))
    return render_template('user_details.html', user=user)

@app.route('/admin/delete_inquiry/<int:inquiry_id>', methods=['POST'])
@login_required
@admin_required
def delete_inquiry(inquiry_id):
    inquiry = db.session.get(PublicInquiry, inquiry_id)
    if not inquiry: flash('Звернення не знайдено.', 'danger'); return redirect(url_for('admin_dashboard'))
    try:
        if inquiry.photo_filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], inquiry.photo_filepath)):
             os.remove(os.path.join(app.config['UPLOAD_FOLDER'], inquiry.photo_filepath))
        db.session.delete(inquiry); db.session.commit()
        flash(f'Звернення №{inquiry.id} було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні звернення: {e}"); traceback.print_exc()
        flash('Під час видалення звернення сталася помилка.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('Користувача не знайдено.', 'danger'); return redirect(url_for('admin_dashboard'))
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
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete:
        flash('Користувача не знайдено.', 'danger'); return redirect(url_for('admin_dashboard'))
    if user_to_delete.is_admin:
        flash('Неможливо видалити адміністратора.', 'danger'); return redirect(url_for('admin_dashboard'))
    try:
        # Видаляємо всі пов'язані дані
        Comment.query.filter_by(user_id=user_id).delete()
        for photo in user_to_delete.photos:
              if photo.filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.filepath))
              if photo.analyzed_filepath and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath)): os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo.analyzed_filepath))
        Photo.query.filter_by(user_id=user_id).delete()
        Enterprise.query.filter_by(user_id=user_id).delete()

        db.session.delete(user_to_delete); db.session.commit()
        flash(f'Користувача "{user_to_delete.username}" та всі його дані було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні користувача: {e}"); traceback.print_exc()
        flash('Під час видалення користувача сталася помилка.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
@login_required
def delete_photo(photo_id):
    photo = db.session.get(Photo, photo_id)
    if not photo:
        flash('Фото не знайдено.', 'danger'); return redirect(url_for('my_photos'))
    if not (current_user.is_admin or current_user.id == photo.user_id):
        flash('У вас немає прав для видалення цього фото.', 'danger'); return redirect(url_for('my_photos'))
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
def delete_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        flash('Коментар не знайдено.', 'danger'); return redirect(url_for('index'))
    if not (current_user.is_admin or current_user.id == comment.user_id):
        flash('У вас немає прав для видалення цього коментаря.', 'danger'); return redirect(url_for('index'))
    try:
        db.session.delete(comment); db.session.commit()
        flash('Коментар було успішно видалено.', 'success')
    except Exception as e:
        db.session.rollback(); print(f"Помилка при видаленні коментаря: {e}"); traceback.print_exc()
        flash('Під час видалення коментаря сталася помилка.', 'danger')
    return redirect(request.referrer or url_for('index'))


@app.cli.command("init-db")
def init_db_command():
    """Створює/очищує базу даних та створює початкових користувачів."""
    db.drop_all()
    db.create_all()
    
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin', is_active=True)
        admin_user.set_password('adminpassword')
        db.session.add(admin_user)
        print("Створено адміністратора.")

    if not User.query.filter_by(username='manager').first():
        manager_user = User(username='manager', role='manager', is_active=True)
        manager_user.set_password('managerpass')
        db.session.add(manager_user)
        print("Створено керівника.")
        
    db.session.commit()
    print("Ініціалізацію бази даних завершено.")


if __name__ == '__main__':
    app.run(debug=True)
