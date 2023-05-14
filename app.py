import sqlite3
import os
from dotenv import load_dotenv, find_dotenv
from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from UserLogin import UserLogin
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

load_dotenv(find_dotenv())

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'alert-danger'
login_manager.init_app(app)

scheduler = BackgroundScheduler()
scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    user = users.get_by_id(user_id)
    if user is not None:
        return UserLogin().create(user)
    else:
        return None


class tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(20), nullable=False)
    task = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(50))
    today = db.Column(db.Boolean, default=True)
    complete = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<Task %r>' % self.id


class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(15), nullable=False)

    @staticmethod
    def get_by_id(user_id):
        return users.query.get(int(user_id))

    @staticmethod
    def get_by_email(email):
        return users.query.filter_by(email=email).first()

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = users.get_by_email(request.form['email'])

        if user and check_password_hash(user.password, request.form['password']):
            userlogin = UserLogin().create(user)
            login_user(userlogin)
            return redirect(url_for('index'))
        elif user:
            flash('An error occurred while logging, Incorrect Email/password!', 'alert-danger')
        else:
            flash('User not found', 'alert-danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully!', 'alert-success')
    return redirect(url_for('login'))


@app.route('/sign-up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        username = request.form['email']
        email = request.form['email']
        password = request.form['password']
        password_conf = request.form['password_conf']
        hash = generate_password_hash(password)

        if len(email) > 4 and len(password) > 4 and password.strip() == password_conf.strip():
            # Check if email already exists in the database
            existing_user = users.query.filter_by(email=email).first()
            if existing_user:
                flash('This email address is already registered. Please choose a different one.', 'alert-danger')
                return render_template('sign-up.html')

            new_user = users(username=username, email=email, password=hash)
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Your registration was successful. <a href="' + url_for('login') + '">Click here to login</a>',
                      'alert-success')

                return redirect('/login')
            except Exception as e:
                flash('An error occurred while registering, please try again later.', 'alert-danger')
        else:
            flash('An error occurred while registering, Wrong input!', 'alert-danger')
            return render_template('sign-up.html')

    else:
        return render_template('sign-up.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


@app.route('/features')
@login_required
def features():
    group_tasks = tasks.query.filter_by(user=current_user.name).order_by(tasks.id.desc()).all()
    return render_template('features.html', group_tasks=group_tasks)


@app.route('/<int:id>/del')
@login_required
def task_delete(id):
    task = tasks.query.get_or_404(id)
    try:
        db.session.delete(task)
        db.session.commit()
        return redirect('/features')
    except:
        return 'Received an error while deleting...'


@app.route('/<int:id>/complete', methods=['POST'])
@login_required
def task_checked(id):
    task = tasks.query.get_or_404(id)

    if task.complete:
        task.complete = False
    else:
        task.complete = True
    try:
        db.session.commit()
        return redirect('/features')
    except:
        return 'Received an error while checking...'


@app.route('/<int:id>/set-next', methods=['GET'])
@login_required
def task_to_next(id):
    task = tasks.query.get_or_404(id)
    if request.method == 'GET':
        task.today = False

        try:
            db.session.commit()
            return redirect('/features')
        except:
            return 'Received an error while setting to next day...'


@app.route('/add-task/<day>', methods=['POST', 'GET'])
@login_required
def add_task(day):
    if request.method == 'POST':
        user = current_user.name
        task = request.form['task']
        time = request.form['time']

        if day == 'today':
            new_task = tasks(user=user, task=task, time=time, today=True)
        elif day == 'tomorrow':
            new_task = tasks(user=user, task=task, time=time, today=False)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/features')
        except:
            return 'Adding task ERROR'
    else:
        return render_template('task.html', day=day)


@app.route('/about')
def about():
    return render_template('about.html')


@app.errorhandler(404)
def pageNotFound(error):
    return render_template('page404.html'), 404


@scheduler.scheduled_job('cron', hour=0)  # define the job that will run every day at midnight
def del_completed():
    with app.app_context():
        completed_tasks = tasks.query.filter_by(complete=True).all()
        if not completed_tasks:
            logging.info("No completed tasks found to delete")
        else:
            for task in completed_tasks:
                try:
                    db.session.delete(task)
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Error while deleting task {task.id}: {str(e)}")
                    db.session.rollback()
            logging.info(f"Deleted {len(completed_tasks)} completed tasks")
        db.session.close()


@scheduler.scheduled_job('cron', hour=0)  # define the job that will run every day at midnight
def transfer_to_next():
    with app.app_context():
        tomorrow_tasks = tasks.query.filter_by(today=False, complete=False).all()
        if not tomorrow_tasks:
            logging.info("No tomorrow tasks found to transfer")
        else:
            for task in tomorrow_tasks:
                try:
                    task.today = True
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Error while transfer task {task.id}: {str(e)}")
                    db.session.rollback()
            logging.info(f"Transfer {len(tomorrow_tasks)} completed tasks")
        db.session.close()


scheduler.add_job(del_completed, 'cron', hour=0)
scheduler.add_job(transfer_to_next, 'cron', hour=0)

if __name__ == '__main__':
    app.run(debug=True)
