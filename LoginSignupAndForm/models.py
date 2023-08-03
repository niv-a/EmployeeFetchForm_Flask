from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime, timedelta, timezone
# from create import *

db = SQLAlchemy()

# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class User(UserMixin, db.Model):
    """ User model """

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=True)
    verified = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(80), unique=True, nullable=False)
    created_date = db.Column(db.Date, default=datetime.utcnow().date())
    created_time = db.Column(db.Time, default=datetime.utcnow().time())
    ip_address = db.Column(db.String(15), nullable=False)

    # def generate_verification_token(self):
    #     return serializer.dumps(self.id)

    # @staticmethod
    # def verify_token(token):
    #     try:
    #         # Token expires after 24 hours
    #         user_id = serializer.loads(token, max_age=86400)
    #         user = User.query.get(user_id)
    #         user.email_verified = True
    #         user.verification_token = None
    #         db.session.commit()
    #         return user
    #     except SignatureExpired:
    #         return None
