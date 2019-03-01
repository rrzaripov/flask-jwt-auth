# project/server/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))
postgres_local_base = 'postgresql://postgres:postgres@localhost/'
database_name = 'auth'


class ProductionConfig:
    """Production configuration."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')
    TTL = os.getenv('TTL', 600)
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost/'
