from mongoengine import Document, StringField, EmailField, IntField

class User(Document):
    username = StringField(db_field='username')
    email = EmailField(db_field='email')
    password = StringField(db_field='password')
    points = IntField(db_field='points')