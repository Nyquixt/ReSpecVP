from flask import Blueprint, render_template

from models.user_model import User

user_app = Blueprint('user_app', __name__)

@user_app.route('/users', methods=['GET', 'POST'])
def view_users():
    users = User.objects()
    print(users)
    return 'good'



@user_app.route('/')
def home():
    return render_template("landingpage.html")


@user_app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")