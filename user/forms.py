from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, validators

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

    email = StringField('Email', [
        validators.Email(),
        validators.DataRequired()
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=4, max=80)
    ])

    confirmed = PasswordField('Confirmed Password', [
        validators.EqualTo('password', message='Passwords must match')
    ])

    def validate_username(self, form, field):
        if User.objects.filter(username=field.data).first():
            raise validators.ValidationError('Username already exist')

    def validate_email(self, form, field):
        if User.objects.filter(email=field.data).first():
            raise validators.ValidationError('Email already exists')
