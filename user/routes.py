from flask import Blueprint, session, request, redirect, url_for, abort, render_template
from utility.decorators import login_required
from models.user_model import User
from user.forms import RegisterForm, LoginForm
import bcrypt

user_app = Blueprint('user_app', __name__)

@user_app.route('/users', methods=['GET', 'POST'])
def view_users():
    users = User.objects()
    print(users)
    return 'good'



@user_app.route('/')
def home():
    return render_template("landingpage.html")




# register
@user_app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            salt = bcrypt.gensalt()
            user = User(
                username = form.username.data,
                password = bcrypt.hashpw(form.password.data, salt)
            ).save()

            return redirect(url_for('user_app.login'))
    
    return render_template('user/register.html', form=form)

# log in
@user_app.route('/login', methods=['GET', 'POST'])
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
                    return redirect(url_for('general_app.index'))
                else:
                    return render_template('user/login.html', error='Incorrect username or password')
            # user does not exist
            else:
                return render_template('user/login.html', error='Not a valid username. Register?')

    return render_template('user/login.html', form=form)

#dashboard
@login_required
@user_app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")


# log out
@login_required
@user_app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('general_app.index'))
