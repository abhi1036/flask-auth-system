# 🔐 Flask User Authentication System

A full-featured authentication system built using Flask and SQLAlchemy.  
Supports user registration, login, email verification, JWT authentication, password reset, and token blacklisting.

## 🚀 Features
- JWT Access & Refresh Tokens
- Role-based Access (Admin/User)
- Email Verification via Flask-Mail
- Password Reset via Token
- Secure Password Hashing (Werkzeug)
- Token Blacklisting for Logout

## ⚙️ Tech Stack
- Python 3.11+
- Flask
- Flask-Mail
- Flask-Migrate
- SQLAlchemy

## 📂 Setup
```bash
pip install -r requirements.txt
python app.py
