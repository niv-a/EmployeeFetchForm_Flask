from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from flask import request
from flask_wtf import FlaskForm, RecaptchaField
from flask_login import current_user
from wtforms.validators import Regexp

# from application import *

import bcrypt
import re


from passlib.hash import pbkdf2_sha256
from models import User
# from application import *
print("k1")


# def verify_emaillink(form, field):
#     username = form.username.data
#     user = User.query.filter_by(username=username).first()

#     if user:
#         if user.verified:
#             return True
#         else:
#             raise ValidationError("Unverified email.")
#     else:
#         raise ValidationError("User not found.")

def verify_emaillink(form, field):
    # Retrieve the entered username from the form field
    # username = field.data
    username = request.form.get('username')

    if User.query.filter_by(username=username).first():
        if User.verified:
            # Email is verified, return True
            return True
        else:
            raise ValidationError("Unverified email.")
    else:
        raise ValidationError("User not found.")


def verify_password(password, hashed_password):
    # Verify if the password matches the hashed password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def invalid_credentials(form, field):
    """ Username and password checker """

    # password = field.data
    # username = form.username.data
    username = request.form.get('username')
    password = request.form.get('password')
    print("k2")
    # print(password)

    # Check username is invalid
    user_object = User.query.filter_by(username=username).first()
    if user_object is None:
        raise ValidationError("Username or password is incorrect")
    # elif pbkdf2_sha256.hash(password) != user_object.password:
    elif not verify_password(password, user_object.password):
        raise ValidationError("Username or password is incorrect")
    print("k3")
    return True
    # Check password in invalid
    # elif not pbkdf2_sha256.verify(password, user_object.password):
    #     raise ValidationError("Username or password is incorrect")


class RegistrationForm(FlaskForm):
    """ Registration form"""

    print("validation started")
    name = StringField('name', validators=[InputRequired(message="Name required"), Length(
        min=4, max=25, message="Enter your name with your designation")])
    username = StringField('emailid', validators=[InputRequired(message="Username required"), Length(
        min=4, max=50, message="Username must be between 4 and 25 characters")])
    password = PasswordField('password', validators=[InputRequired(message="Password required"), Length(
        min=4, max=25), Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=])[A-Za-z\d@#$%^&+=]+$', message="Password must be between 4 and 25 characters")])
    submit_button = SubmitField('Sign Up')
    print("k4")
    # confirm_pswd = PasswordField('confirm_pswd', validators=[InputRequired(
    #     message="Password required"), EqualTo('password', message="Passwords must match")])
    # print(name)

    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()

        if user_object:
            raise ValidationError(
                "Username already exists. Select a different username.")
        print("k5")


class LoginForm(FlaskForm):
    """ Login form """

    username = StringField('emailid', validators=[
                           InputRequired(message="Username required"), verify_emaillink])
    password = PasswordField('password', validators=[InputRequired(
        message="Password required"), invalid_credentials])
    recaptcha = RecaptchaField()
    submit = SubmitField('submit')
    print("k6")

    # print(username)
    # print(password)

# class LoginForm(FlaskForm):
#     """ Login form """

#     username = StringField('emailid', validators=[
#                            InputRequired(message="Username required")])
#     password = PasswordField('password', validators=[InputRequired(
#         message="Password required"), invalid_credentials])
#     submit = SubmitField('submit')


# login_form = LoginForm()
# print(login_form.username)  # Access the username field instance
# print(login_form.password)  # Access the password field instance
