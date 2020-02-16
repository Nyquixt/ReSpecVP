from flask import Flask
from flask_mongoengine import MongoEngine
from flask import Blueprint, session, request, redirect, url_for, abort, render_template

# form funcs
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, DateTimeField, IntegerField, validators

# utility imports
from functools import wraps
import bcrypt

app = Flask(__name__)

# cfg
app.config['SECRET_KEY'] = 'ReSpecVP'
app.config['MONGODB_SETTINGS'] = {
    'db': 'respecvp',
    'host': '127.0.0.1',
    'port': 27017
}

db = MongoEngine(app)

# decorators

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in session:
            return f(*args, **kwargs)
        return redirect(url_for('user_app.login'))
    return decorated_function

# models

class User(db.Document):
    username = db.StringField(db_field='username')
    password = db.StringField(db_field='password')
    points = db.IntField(db_field='points')

class Event(db.Document):
    name = db.StringField(db_field='name')
    time = db.DateTimeField(db_field='time')
    location = db.StringField(db_field='location')
    max_participants = db.IntField(db_field='max_ppl')
    host = db.ReferenceField(User, db_field='host_person')
    desc = db.StringField(db_field='desc')

class Request(db.Document):
    name = db.StringField(db_field='name')
    time = db.DateTimeField(db_field='time')
    desc = db.StringField(db_field='desc')


""" Forms """
# user
class LoginForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.length(min=4, max=25)
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=4, max=80)
    ])

class RegisterForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.length(min=4, max=25)
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=4, max=80)
    ])

    confirmed = PasswordField('Confirmed Password', [
        validators.EqualTo('password', message='Passwords must match')
    ])

    def validate_username(form, field):
        if User.objects.filter(username=field.data).first():
            raise validators.ValidationError('Username already exists')

    def validate_email(form, field):
        if User.objects.filter(email=field.data).first():
            raise validators.ValidationError('Email already exists')

# event
class EventForm(FlaskForm):
    name = StringField('Name', [
        validators.DataRequired(),
        validators.length(min=4, max=50)
    ])

    time = DateTimeField('Time', [
        validators.DataRequired()
    ])

    location = StringField('Location', [
        validators.DataRequired()
    ])

    max_ppl = IntegerField('Max Participants')

    desc = TextAreaField('Description')

""" Routes """
# register
@app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            salt = bcrypt.gensalt()

            User(
                username = form.username.data,
                password = bcrypt.hashpw(form.password.data, salt)
            ).save()

            return redirect(url_for('login'))
    
    return render_template('user/register.html', form=form)

# log in
@app.route('/login', methods=['GET', 'POST'])
def login():

    # login form class from forms.py
    form = LoginForm()

    # if no validation errors search for user
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.objects.filter(
                username=form.username.data.lower().strip()
            ).first()

            # if user exist check password
            if user:
                if bcrypt.hashpw(form.password.data, user.password) == user.password:
                    session['username'] = form.username.data  # set the session variables
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('user/login.html', error='Incorrect username or password')
            # user does not exist
            else:
                return render_template('user/login.html', error='Not a valid username. Register?')

    return render_template('user/login.html', form=form)

# dashboard
@login_required
@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

# log out
@login_required
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('index'))

# events
@login_required
@app.route('/event/upload', methods=['GET', 'POST'])
def upload_event():
    if 'username' in session:

        form = EventForm()

        if request.method == 'POST':
            if form.validate_on_submit():
                new_event = Event()
                new_event.name = form.name.data
                new_event.time = form.time.data
                new_event.location = form.location.data
                
                if form.max_ppl.data:
                    new_event.max_participants = form.max_ppl.data

                if form.desc.data:
                    new_event.desc = form.desc.data

                host = User.objects.get(username=session['username'])

                if host is None:
                    return abort(403)

                new_event.host = host
                new_event.save()

                return redirect(url_for('index'))
        return render_template('event/upload_event.html', form=form)
    else:
        return abort(403)

# edit events
@login_required
@app.route('/event/edit/<id>', methods=['GET', 'POST'])
def edit_event(id):
    if 'username' in session:
        try:
            event = Event.objects.get(id=id)
        except:
            return abort(404)

        user = User.objects.get(username=session['username'])

        if user.id == event.host.id: # valid user to edit
            form = EventForm(
                name=event.name,
                time=event.time,
                location=event.location,
            )

            if event.max_participants:
                form.max_ppl.data = event.max_participants
            
            if event.desc:
                form.desc.data = event.desc

            if request.method == 'POST':
                if form.validate_on_submit():

                    event.name = form.name.data
                    event.time = form.time.data
                    event.location = form.location.data
                    
                    event.max_participants = form.max_ppl.data

                    event.desc = form.desc.data
                    print(form.desc.data)
                    event.save()

                    return redirect(url_for('index'))
        else:
            return abort(403)

        return render_template('event/edit_event.html', form=form)
    else:
        return abort(403)

# general routes
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

