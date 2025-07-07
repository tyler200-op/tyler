import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '123'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''  # Empty password
    MYSQL_DB = 'employee_management'
    MYSQL_CURSORCLASS = 'DictCursor'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)