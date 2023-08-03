import bcrypt
from create import *
from models import *
from wtform_fields import *
import secrets
from flask_mail import Mail, Message
import os
from flask import Flask, render_template, request, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm, RecaptchaField
from flask_login import LoginManager, login_user, current_user, logout_user
import psycopg2
import re
from flask import Flask, send_from_directory
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import random
from datetime import datetime, timedelta, timezone

# from modules.auth import *
# from modules.home import *
# from modules.helpers import *

"""
Imported dotenv to load the config file
"""
from dotenv import load_dotenv


# ================= MAIN CODE ==================

# lOADING ENV FILE
load_dotenv()

print(os.getenv('DB_PORT'))
DB_PORT = int(os.getenv('DB_PORT'))
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')


def connect_to_database():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn


print("Database connected")


def is_valid_search_value(search_value):
    pattern = r'^[a-zA-Z0-9\s]+$'
    return re.match(pattern, search_value) is not None


def fetch_entries(column, search_value):
    conn = connect_to_database()
    cursor = conn.cursor()

    query = """SELECT emp_code, emp_name, emp_desig, mobile, location FROM employee_details
           WHERE lower({}) ILIKE lower('%{}%') """

    if column == 'emp_code':
        column_name = 'emp_code'
        query = query.format(column_name, search_value)
        # cursor.execute(query)

    elif column == 'emp_name':
        column_name = 'emp_name'
        query = query.format(column_name, search_value)
        # cursor.execute(query)

    elif column == 'emp_desig':
        column_name = 'emp_desig'
        query = query.format(column_name, search_value)
        # cursor.execute(query)

    elif column == 'mobile':
        # column_name = "mobile ILIKE '%{}%' OR mobile2 ILIKE '%{}%'".format(
        #     search_value, search_value)
        # query = query.format(column_name, search_value)
        column_name = "mobile ILIKE '%{}%'".format(search_value, search_value)
        query = query.format(column_name, search_value)
        # cursor.execute(query)

    elif column == 'location':
        column_name = 'location'
        query = query.format(column_name, search_value)
        # cursor.execute(query)

    # if column != 'all_info':
    #     cursor.execute(query)
    #     print("5678")

# Substitute the column name and search value into the query


# --------------------------------------------------------------

    cursor.execute(query)
    entries = cursor.fetchall()
    cursor.close()
    conn.close()
    print(column)

    return entries

# 2222222222222222222222222222222222222222222222222222222222222


# Initialize login manager
login = LoginManager(app)
login.init_app(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # entry
app.config['MAIL_PORT'] = 465  # or the appropriate port for your mail server
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# give senders email that sends verification mail

"""
Shift confidential details to .env file
"""
app.config['MAIL_USERNAME'] = os.getenv('SENDERS_EMAIL')
# app password or th email password of the sender email
app.config['MAIL_PASSWORD'] = os.getenv('SENDERS_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv(
    'SENDERS_DEFAULT_EMAIL')  # set default email

mail = Mail(app)

# enter recaptcha public key
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
# have to hide it
# enter recaptcha private key
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
app.config['TESTING'] = True


# To generate a 6 digit random OTP
def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    # try:
    msg = Message('Email Verification',
                  sender='your_email@example.com', recipients=[email])
    msg.body = f'Your OTP for email verification is: {otp}'
    mail.send(msg)


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def send_verification_email(username, verification_link):
    msg = Message('Email Verification',
                  sender='your_email@example.com', recipients=[username])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    mail.send(msg)


def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf8')


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/", methods=['GET', 'POST'])
def index():

    # if request.method == 'POST':

    print("1")
    reg_form = RegistrationForm()

    # print(name)
    print(reg_form.validate_on_submit())
    print(request.form.get('name'))
    print(reg_form.errors)
    if reg_form.validate_on_submit():
        #
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = (request.remote_addr)
        print("2")

    # Hash password
        password = hash_password(password)
        token = serializer.dumps(username, salt='email-confirm')

        print("3")

    # Add username & hashed password to DB
        user = User(name=name, username=username,
                    token=token, password=password, created_by=username, created_date=datetime.utcnow().date(),
                    created_time=datetime.utcnow().time(), ip_address=ip_address)
        db.session.add(user)
        db.session.commit()
        print("4")

        verification_link = url_for(
            'verify_email', token=token, _external=True)
        send_verification_email(username, verification_link)

        flash('Registered successfully.Please check your email to verify.', 'success')

        return redirect(url_for('login'))

    return render_template("signup.html", form=reg_form)
    # else:
    #     return render_template("signup.html", form=reg_form)


@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        username = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(username=username).first()
        if user:
            user.verified = True
            db.session.commit()
            flash('Email verified successfully!', 'success')
        else:
            flash('Invalid or expired verification token.', 'danger')
    except SignatureExpired:
        flash('Invalid or expired verification token.', 'danger')

    return redirect(url_for('login'))


# @app.route('/login_otp', methods=['GET', 'POST'])
# def login_otp():
#     if request.method == 'POST':
#         otp = request.form['otp']

#         # Get the sign-up data from the session
#         login_data = session.get('login_data')

#         if login_data['otp'] == otp:
#             # Clear the session data
#             session.pop('login_data')
#             session['logged_in'] = True
#             return redirect('dashboard')
#         else:
#             flash("Invalid OTP. Please try again.", "error")
#             return render_template('login_otp.html')
#     else:
#         return render_template('login_otp.html')

@app.route('/login_otp', methods=['GET', 'POST'])
def login_otp():
    if request.method == 'POST':
        otp = request.form['otp']

        # Get the sign-up data from the session
        login_data = session.get('login_data')

        if login_data['otp'] == otp:
            otp_creation_time = login_data['otp_creation_time']
            time_difference = datetime.now(timezone.utc) - otp_creation_time

            if time_difference <= timedelta(minutes=10):
                # Clear the session data
                session.pop('login_data')

                # Set the user as logged in
                session['logged_in'] = True

                # Redirect to the home page
                return redirect('dashboard')
            else:
                flash("OTP has expired. Login again.", "error")
                return render_template('login_otp.html')
    else:
        return render_template('login_otp.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    print("THIS IS ACCESSED")
    login_form = LoginForm()
    # print(login_form)
    print(login_form.validate_on_submit())
    print(request.form.get('username'))
    print(login_form.errors)
    # print(login_form.verify_emaillink())
    # print(login_form.username.data)

    otp = generate_otp()

    session['login_data'] = {
        'otp': otp,
        'otp_creation_time': datetime.now(timezone.utc)}

    # Allow login if validation success
    if login_form.validate_on_submit():
        print(login_form.validate_on_submit())
        # print(login_form.verify_emaillink())
        print(request.form.get('name'))
        print(login_form.errors)
        print(login_form.username.data)
        user_object = User.query.filter_by(
            username=login_form.username.data).first()
        if user_object.verified:
            email = user_object.username
            send_otp_email(email, otp)
            login_user(user_object)
            print("THIS IS ACCESSEDdd")
            return redirect(url_for('login_otp'))
        # else:
        #     flash('Invalid email or password', 'danger')
        #     return render_template("login.html", form=login_form)
    flash('Invalid email or password', 'danger')
    return render_template("login.html", form=login_form)


@app.route("/logout", methods=['GET'])
def logout():

    # Logout user
    logout_user()
    flash('You have logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])
def search_form():
    if request.method == 'POST':
        try:
            search_value = request.form['search_value'].strip()
            if is_valid_search_value(search_value):
                column = request.form['column']
                entries = fetch_entries(column, search_value)
                print(search_value)
                print(entries)
                print("g1")
                return render_template('form.html', entries=entries)
            else:
                # Invalid search value, display an error message or take appropriate action
                raise ValueError(
                    "Invalid search value. Only letters, numbers, and spaces are allowed.")
        except ValueError as e:
            flash(str(e), "error")
            # Return a response in case of error
            return render_template('form.html', entries=None)
    else:
        print("g2")
        return render_template('form.html', entries=None)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    return render_template('forgot.html')


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')


if __name__ == "__main__":
    app.run(debug=True)
