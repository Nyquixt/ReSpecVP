from flask import Blueprint, render_template

general_app = Blueprint('general_app', __name__)

@general_app.route('/', methods=['GET'])
def index():
    return render_template('index.html')