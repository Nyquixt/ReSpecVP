from flask import Flask
from mongoengine import connect

# blueprint imports
from general.routes import general_app
from user.routes import user_app
from event.routes import event_app
from request.routes import request_app

app = Flask(__name__)
connect('respecvp', host='localhost:27017', alias='main_conn')

app.register_blueprint(general_app)
app.register_blueprint(user_app)
app.register_blueprint(event_app)
app.register_blueprint(request_app)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

