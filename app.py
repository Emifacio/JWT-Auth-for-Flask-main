from flask import Flask, jsonify
from auth import auth_bp
from users import user_bp
from models import User, TokenBlocklist
from os import environ
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from database import db, jwt
from flask_cors import CORS
import os


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DATABASE_URL')
    app.config['JWT_SECRET_KEY'] = os.environ.get('FLASK_JWT_SECRET_KEY')
    db.init_app(app)
    jwt.init_app(app)
 
    with app.app_context():
        db.create_all()  # Crea todas las tablas definidas en tus modelos
      
    # register bluepints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(user_bp, url_prefix="/users")



    # load user
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_headers, jwt_data):
        identity = jwt_data["sub"]
        user = User.query.get(identity)
        print(f"User ID from JWT: {identity}")
        print(f"User loaded from database: {user}")
        return user

    # additional claims

    @jwt.additional_claims_loader
    def make_additional_claims(identity):
        if identity == "test":
            return {"is_staff": True}
        return {"is_staff": False}

    # jwt error handlers

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({"message": "Token has expired", "error": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify(
                {"message": "Signature verification failed", "error": "invalid_token"}
            ),
            401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {
                    "message": "Request doesnt contain valid token",
                    "error": "authorization_header",
                }
            ),
            401,
        )
    
    @jwt.token_in_blocklist_loader
    def token_in_blocklist_callback(jwt_header,jwt_data):
        jti = jwt_data['jti']

        token = db.session.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).scalar()

        return token is not None

    return app

app = create_app()