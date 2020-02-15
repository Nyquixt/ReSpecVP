from mongoengine import Document, DateTimeField, StringField, ReferenceField, IntField
from models.user_model import User

class Event(Document):
    name = StringField(db_field='name')
    time = DateTimeField(db_field='time')
    location = StringField(db_field='location')
    lng = StringField(db_field='longitude')
    lat = StringField(db_field='latitude')
    max_participants = IntField(db_field='max_ppl')
    host = ReferenceField(User, db_field='host_person')
    desc = StringField(db_field='desc')