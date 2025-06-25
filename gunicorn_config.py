bind = "0.0.0.0:10000"
workers = 4
accesslog = "-"
errorlog = "-"
preload_app = True

def when_ready(server):
    # Ця команда створює таблиці в базі даних при старті
    from app import db, User
    with server.app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpassword')
            db.session.add(admin_user)
            db.session.commit()
            print("Базу даних та адміністратора створено.")