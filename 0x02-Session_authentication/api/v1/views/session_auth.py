#!/usr/bin/env python3
"""
Module session_auth
"""
from flask import abort, jsonify, request
from api.v1.views import app_views
from os import getenv
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """
    View for user login
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

    # import auth here to avoid circular import error
    # else can break first tasks
    from api.v1.app import auth

    user = users[0]

    session_id = auth.create_session(user.id)
    session_name = getenv("SESSION_NAME")

    response = jsonify(user.to_json())
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """
    Logout user
    """
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)

    return jsonify({}), 200
