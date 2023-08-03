import os
from flask import Flask
from flask_mail import Mail, Message
from models import *
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__)
app.config.from_pyfile('config.cfg')

# database connection string here where user detail table is getting stores
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
print("j1")

db.init_app(app)
print("j2")


def main():
    db.create_all()
    print("j3")


if __name__ == "__main__":
    with app.app_context():
        main()
        print("j4")
