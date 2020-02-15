from flask import Blueprint

from models.user_model import User

user_app = Blueprint('user_app', __name__)

@user_app.route('/users', methods=['GET', 'POST'])
def view_users():
    users = User.objects()
    print(users)
    return 'good'