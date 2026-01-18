#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User

class Signup(Resource):
    def post(self):
        json = request.get_json()
        
        username = json.get('username')
        password = json.get('password')
        
        if not username or not password:
            return {'error': 'Username and password are required'}, 422
        
        # Create new user with hashed password
        user = User(username=username)
        user.password_hash = password  # This will use the setter to hash the password
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Save user ID in session
            session['user_id'] = user.id
            
            # Return user object as JSON
            return user.to_dict(), 201
        
        except IntegrityError:
            return {'error': 'Username already exists'}, 422


class CheckSession(Resource):
    def get(self):
        # Check if user is authenticated
        user_id = session.get('user_id')
        
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return user.to_dict(), 200
        
        # User not authenticated
        return {}, 204


class Login(Resource):
    def post(self):
        json = request.get_json()
        
        username = json.get('username')
        password = json.get('password')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return {'error': 'Invalid username or password'}, 401
        
        # Authenticate password using bcrypt
        if user.authenticate(password):
            # Save user ID in session
            session['user_id'] = user.id
            return user.to_dict(), 200
        
        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        # Remove user_id from session
        session['user_id'] = None
        return {}, 204


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)