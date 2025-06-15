from flask import Flask, jsonify
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from extensions import db, migrate, mail  # ✅ Import mail here
from .routes.user_routes import user_bp
from models import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'myverysecretkey12345'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ ADD Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abhigadekar34@gmail.com'
app.config['MAIL_PASSWORD'] = 'dyjnzhfbokpfyqij'
app.config['MAIL_DEFAULT_SENDER'] = 'abhigadekar34@gmail.com'  # your Gmail



# ✅ Initialize extensions
db.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)  # ✅ Initialize mail

app.register_blueprint(user_bp)
