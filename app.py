from flask import Flask
from flask_mongoengine import MongoEngine
from flask import Blueprint, session, request, redirect, url_for, abort, render_template

# form funcs
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, DateTimeField, IntegerField, validators

# utility imports
from functools import wraps
import bcrypt
import json

app = Flask(__name__)

# cfg
app.config['SECRET_KEY'] = 'ReSpecVP'
app.config['MONGODB_SETTINGS'] =  {
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
    rsvp = db.ListField(db_field='rsvp')

class Request(db.Document):
    name = db.StringField(db_field='name')
    time = db.DateTimeField(db_field='time')
    desc = db.StringField(db_field='desc')
    host = db.ReferenceField(User, db_field='host_person')
    accepted = db.BooleanField(db_field='accepted', default=False)
    accepted_by = db.ReferenceField(User, db_field='accepted_by')


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

                    return render_template('user/login.html', form=form, error='Incorrect username or password')
            # user does not exist
            else:
                return render_template('user/login.html', form=form, error='Not a valid username. Register?')

    return render_template('user/login.html', form=form)

# dashboard
@login_required
@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'username' in session:
        events = Event.objects().order_by('time')
        requests = Request.objects().order_by('time')
        user_id = User.objects.get(username=session['username']).id
        return render_template('dashboard.html', events=events, requests=requests, user_id=user_id)
    else:
        return abort(403)

# log out
@login_required
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('index'))

# upload event
@login_required
@app.route('/event/upload', methods=['POST'])
def upload_event():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)
            user = User.objects.get(username=session['username'])
            
            event = Event()
            event.name = data['event-name']
            event.time = data['event-time']
            event.location = data['event-location']
            event.max_participants = data['event-ppl']
            event.desc = data['event-desc']
            event.host = user
            event.save()

            return {
                "status": "success"
            }
        return {
            "status": "fail"
        }
    else:
        return abort(403)

# upload request
@login_required
@app.route('/request/upload', methods=['POST'])
def upload_request():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)
            user = User.objects.get(username=session['username'])
            
            req = Request()
            req.name = data['request-name']
            req.time = data['request-time']
            req.desc = data['request-desc']
            req.host = user
            req.save()

            return {
                "status": "success"
            }
        return {
            "status": "fail"
        }
    else:
        return abort(403)

@login_required
@app.route('/event/rsvp', methods=['POST'])
def rsvp():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)

            event = Event.objects.get(id=data['event-id'])
            user = User.objects.get(username=session['username'])

            rsvp_list = event.rsvp

            if len(rsvp_list) < event.max_participants: # add if not exceed max ppl
                print('adding')
                rsvp_list.append(user.id)
            else:
                return {
                    "status": "Max RSVP Reached !"
                }

            event.rsvp = rsvp_list
            event.save()

            return {
                "status": "success"
            }
        return {
            "status": "failed..."
        }
    else:
        return abort(403)

@login_required
@app.route('/event/cancelrsvp', methods=['POST'])
def cancel_rsvp():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)

            event = Event.objects.get(id=data['event-id'])
            user = User.objects.get(username=session['username'])

            rsvp_list = event.rsvp
            rsvp_list.remove(user.id)

            event.rsvp = rsvp_list
            event.save()

            return {
                "status": "success"
            }
        return {
            "status": "failed..."
        }
    else:
        return abort(403)

@login_required
@app.route('/request/accept', methods=['POST'])
def accept():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)

            req = Request.objects.get(id=data['req-id'])
            user = User.objects.get(username=session['username'])

            req.accepted = True
            req.accepted_by = user

            req.save()

            return {
                "status": "success"
            }
        return {
            "status": "failed..."
        }
    else:
        return abort(403)

@login_required
@app.route('/request/unaccept', methods=['POST'])
def unaccept():
    if 'username' in session:
        if request.method == 'POST':
            data = json.loads(request.data)

            req = Request.objects.get(id=data['req-id'])
            user = User.objects.get(username=session['username'])

            req.accepted = False
            req.accepted_by = None

            req.save()

            return {
                "status": "success"
            }
        return {
            "status": "failed..."
        }
    else:
        return abort(403)

# general routes
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

