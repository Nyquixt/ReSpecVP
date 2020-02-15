from flask import Flask
from mongoengine import connect

# blueprint imports
from user.routes import user_app

app = Flask(__name__)
connect('respecvp', host='localhost:27017', alias='main_conn')

app.register_blueprint(user_app)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

