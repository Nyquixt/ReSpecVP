from mongoengine import Document, DateTimeField, StringField

class Request(Document):
    name = StringField(db_field='name')
    time = DateTimeField(db_field='time')
    desc = StringField(db_field='desc')