#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema


class ClearSession(Resource):

    def delete(self):

        session['page_views'] = None
        session['user_id'] = None

        return {}, 204


class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {"error": "Username and password required"}, 400

        # Check for existing user
        if User.query.filter_by(username=username).first():
            return {"error": "Username already exists"}, 409

        # Create new user and hash password
        user = User(username=username)
        user.password_hash = password  # trigger the bycrypt hashing

        db.session.add(user)
        db.session.commit()

        # Log in the user by setting session
        session['user_id'] = user.id

        return UserSchema().dump(user), 201


class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        # Validate input
        if not username or not password:
            return {"error": "Username and password required"}, 400

        # Lookup user
        user = User.query.filter_by(username=username).first()

        # Authenticate password
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        # Unauthorized response
        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return {}, 204

        user = User.query.get(user_id)
        if user:
            return UserSchema().dump(user), 200

        return {}, 204  # Fallback session exists but user not found


api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
