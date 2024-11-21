from flask import Flask, request, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from tinydb import TinyDB, Query
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

# Inisialisasi Database
db = TinyDB('/tmp/users.json')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    User_Query = Query()
    result = db.search(User_Query.id == user_id)
    if result:
        user_data = result[0]
        return User(user_data['id'], user_data['username'], user_data['password'])
    return None

def login_route(request):
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        User_Query = Query()
        result = db.search(User_Query.username == username)
        
        if result and check_password_hash(result[0]['password'], password):
            user = User(result[0]['id'], username, result[0]['password'])
            login_user(user)
            return jsonify({"status": "success", "message": "Login berhasil"})
        else:
            return jsonify({"status": "error", "message": "Login gagal"})
    return jsonify({"status": "error", "message": "Metode tidak diizinkan"})

def register_route(request):
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        User_Query = Query()
        existing_user = db.search(User_Query.username == username)
        
        if existing_user:
            return jsonify({"status": "error", "message": "Username sudah terdaftar"})
        
        hashed_password = generate_password_hash(password)
        db.insert({
            'id': len(db) + 1,
            'username': username, 
            'password': hashed_password
        })
        
        return jsonify({"status": "success", "message": "Registrasi berhasil"})
    return jsonify({"status": "error", "message": "Metode tidak diizinkan"})

def handler(request):
    if request.path == '/api/login':
        return login_route(request)
    elif request.path == '/api/register':
        return register_route(request)
    else:
        return jsonify({"status": "error", "message": "Rute tidak ditemukan"})
