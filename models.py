from database import db
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import request, jsonify, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity

def generate_uuid():
    return str(uuid4())
    

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True, default=generate_uuid())
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False)
    password = db.Column(db.Text())
    events = db.relationship('Event', back_populates='user', lazy=True)
    

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @classmethod
    def get_user_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def get_user_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class TokenBlocklist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jti = db.Column(db.String(), nullable=True)
    create_at = db.Column(db.DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return f"<Token {self.jti}>"
    
    def save(self):
        db.session.add(self)
        db.session.commit()
        
        
class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.String, primary_key=True, default=generate_uuid())
    name = db.Column(db.String(80), nullable=False)
    date = db.Column(db.String(80), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='events', lazy=True)
    
    def json(self):
        return {'id': self.id,'name': self.name, 'date': self.date, 'location': self.location, 'description': self.description, 'user_id': self.user_id}
  
