from flask import Blueprint, jsonify, request, jsonify, make_response, abort
from models import User, Event
from database import db
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt,
    current_user,
    get_jwt_identity,
)
from models import User, TokenBlocklist

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/register")
def register_user():
    data = request.get_json()

    user = User.get_user_by_username(username=data.get("username"))

    if user is not None:
        return jsonify({"error": "User already exists"}), 409

    new_user = User(username=data.get("username"), email=data.get("email"))

    new_user.set_password(password=data.get("password"))

    new_user.save()

    return jsonify({"message": "User created"}), 201


@auth_bp.post("/login")
def login_user():
    data = request.get_json()

    user = User.get_user_by_username(username=data.get("username"))

    if user and (user.check_password(password=data.get("password"))):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        return (
            jsonify(
                {
                    "message": "Logged In ",
                    "tokens": {"access": access_token, "refresh": refresh_token},
                }
            ),
            200,
        )

    return jsonify({"error": "Invalid username or password"}), 400


@auth_bp.get("/whoami")
@jwt_required()
def whoami():
    return jsonify(
        {
            "message": "message",
            "user_details": {
                "username": current_user.username,
                "email": current_user.email,
            },
        }
    )


@auth_bp.get("/refresh")
@jwt_required(refresh=True)
def refresh_access():
    identity = get_jwt_identity()

    new_access_token = create_access_token(identity=identity)

    return jsonify({"access_token": new_access_token})


@auth_bp.get('/logout')
@jwt_required(verify_type=False) 
def logout_user():
    jwt = get_jwt()

    jti = jwt['jti']
    token_type = jwt['type']

    token_b = TokenBlocklist(jti=jti)

    token_b.save()

    return jsonify({"message":"Loged Out Successfully"}) , 200


# create event
@auth_bp.post('/event')
@jwt_required()
def create_event():
  try:
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
      abort(404, description="User not found")
    data = request.get_json()
    new_event = Event(name=data['name'], date=data['date'], location=data['location'], description=data['description'], user_id=user.id)
    db.session.add(new_event)
    db.session.commit()   
 
    return jsonify({'message': 'Event created successfully', 'event_id': new_event.id}), 201

  except Exception as e:
    db.session.rollback()
    return make_response(jsonify({'message': 'error creating event', 'error': str(e)}), 500)
  
# get all events
@auth_bp.get('/events')
@jwt_required()
def get_events():
  try:
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)  
    events = user.events
    events_data = [{'id': event.id, 'name': event.name, 'date': event.date, 'location': event.location, 'description': event.description} for event in events]
    return jsonify(events_data), 200
  except Exception as e:
    return make_response(jsonify({'message': 'error getting events', 'error': str(e)}), 500)
  
# get a event by id
@auth_bp.get('/events/<id>')
@jwt_required()
def get_event(id):
  try:
    current_user_id = get_jwt_identity()
    event = Event.query.filter_by(id=id, user_id=current_user_id).first() # get the first event with the id
    if event:
      return make_response(jsonify({'event': event.json()}), 200)
    return make_response(jsonify({'message': 'event not found'}), 404) 
  except Exception as e:
    return make_response(jsonify({'message': 'error getting event', 'error': str(e)}), 500)
  
# update a event by id
@auth_bp.put('/events/<id>')
@jwt_required()
def update_event(id):
  try:
    current_user_id = get_jwt_identity()
    event = Event.query.filter_by(id=id, user_id=current_user_id).first()
    if event:
      data = request.get_json()
      event.name = data['name']
      event.date = data['date']
      event.location = data ['location']
      event.description = data ['description'] 
      db.session.commit()
      return make_response(jsonify({'message': 'event updated'}), 200)
    return make_response(jsonify({'message': 'event not found'}), 404)  
  except Exception as e:
      return make_response(jsonify({'message': 'error updating event', 'error': str(e)}), 500)

# delete a event by id
@auth_bp.delete('/events/<id>')
@jwt_required()
def delete_event(id):
  try:
    current_user_id = get_jwt_identity()
    event = Event.query.filter_by(id=id, user_id=current_user_id).first()
    if event:
      db.session.delete(event)
      db.session.commit()
      return make_response(jsonify({'message': 'event deleted'}), 200)
    return make_response(jsonify({'message': 'event not found'}), 404) 
  except Exception as e:
    return make_response(jsonify({'message': 'error deleting event', 'error': str(e)}), 500) 