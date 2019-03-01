# project/server/auth/views.py
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User

auth_blueprint = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    # Метод для добавления пользователя с логином и паролем
    def post(self):
        post_data = request.get_json()
        user = User.query.filter_by(login=post_data.get('login')).first()
        if not user:
            try:
                user = User(
                    login=post_data.get('login'),
                    password=post_data.get('password')
                )
                db.session.add(user)
                db.session.commit()
                response_object = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                }
                response = make_response(jsonify(response_object)), 201
                return response
            except Exception as e:
                response_object = {
                    'status': 'error',
                    'message': 'Wrong request.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'error',
                'message': 'User already exists.',
            }
            return make_response(jsonify(response_object)), 202


class LoginAPI(MethodView):
    # Аутентификация с логином и паролем
    def post(self):
        post_data = request.get_json()
        try:
            user = User.query.filter_by(login=post_data.get('login')).first()
            valid = bcrypt.check_password_hash(user.password, post_data.get('password'))
            if user and valid:
                auth_token = user.encode_auth_token(user.id)
                refresh_token = user.encode_refresh_token(user.id, user.login)
                if auth_token:
                    response_object = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode(),
                        'refresh_token': refresh_token.decode()
                    }
                    return make_response(jsonify(response_object)), 200
            else:
                response_object = {
                    'status': 'error',
                    'message': 'Authentication failed.'
                }
                return make_response(jsonify(response_object)), 401
        except Exception as e:
            response_object = {
                'status': 'error',
                'message': 'Internal server error.'
            }
            return make_response(jsonify(response_object)), 500


class RefreshAPI(MethodView):
    # Получение нового токена при помощи refresh-токена
    def post(self):
        refresh_header = request.headers.get('Authorization')
        if refresh_header:
            try:
                refresh_token = refresh_header.split(" ")[1]
            except IndexError:
                response_object = {
                    'status': 'error',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            refresh_token = ''
        if refresh_token:
            resp = User.decode_token(refresh_token)
            if not isinstance(resp, str):
                user, login = resp
                user = User.query.filter_by(id=user).first()
                auth_token = user.encode_auth_token(user.id)
                refresh_token = user.encode_refresh_token(user.id, user.login)
                response_object = {
                    'status': 'success',
                    'auth_token': auth_token.decode(),
                    'refresh_token': refresh_token.decode()
                }
                return make_response(jsonify(response_object)), 200
            response_object = {
                'status': 'error',
                'message': resp
            }
            return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'error',
                'message': 'Authentication failed.'
            }
            return make_response(jsonify(response_object)), 401


class UserAPI(MethodView):
    # Метод для проверки корректности авторизации
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                response_object = {
                    'status': 'error',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                response_object = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'login': user.login,
                    }
                }
                return make_response(jsonify(response_object)), 200
            response_object = {
                'status': 'error',
                'message': resp
            }
            return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'error',
                'message': 'Authentication failed.'
            }
            return make_response(jsonify(response_object)), 401


registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
refresh_view = RefreshAPI.as_view('refresh_api')


auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/refresh',
    view_func=refresh_view,
    methods=['POST']
)