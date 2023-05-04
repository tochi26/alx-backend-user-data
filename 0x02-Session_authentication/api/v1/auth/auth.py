#!/usr/bin/env python3
"""
Module auth
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """
    Class to manage the
    API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Defines routes which don't
        need authentication
        """
        if not path or not excluded_paths:
            return True
        if path in excluded_paths:
            return False
        if path[-1] != '/' and path + '/'\
                in excluded_paths:
            return False
        for p in excluded_paths:
            if p.endswith('*') and\
                    path.startswith(p[:-1]):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Returns authorization header
        """
        if not request or not request.headers or\
                not request.headers.get('Authorization'):
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        gets current user info
        """
        return None

    def session_cookie(self, request=None):
        """
        Returns a cookie value from a request
        """
        if not request:
            return None

        cookie = request.cookies.get(getenv('SESSION_NAME'))
        return cookie
