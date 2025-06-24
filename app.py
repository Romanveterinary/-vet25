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
# !!!!!!!!!!! НОВИЙ КОД ДЛЯ СТВОРЕННЯ ТАБЛИЦЬ НА RENDER !!!!!!!!!!!
# ====================================================================
with app.