from flask import Flask, request, jsonify
import os
import json
import jwt
import datetime
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient(os.getenv('MONGODB_URI'))
db = client.userdb
users_collection = db.users

def generate_token(user_id):
    """Generate JWT Token"""
    payload = {
        'user_id': str(user_id),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET', 'fallback_secret'), algorithm='HS256')

def verify_token(token):
    """Verify JWT Token"""
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET', 'fallback_secret'), algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def handler(request):
    """Main request handler"""
    try:
        # Determine method and parse request body
        method = request.method
        data = request.get_json() or {}

        if method == 'POST':
            # User Registration
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'error': 'Username dan password diperlukan'}), 400
            
            existing_user = users_collection.find_one({'username': username})
            if existing_user:
                return jsonify({'error': 'Username sudah terdaftar'}), 409
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user_data = {
                'username': username,
                'password': hashed_password
            }
            
            result = users_collection.insert_one(user_data)
            token = generate_token(result.inserted_id)
            
            return jsonify({'token': token}), 201
        
        elif method == 'GET':
            # User Login
            username = data.get('username')
            password = data.get('password')
            
            user = users_collection.find_one({'username': username})
            if user and bcrypt.check_password_hash(user['password'], password):
                token = generate_token(user['_id'])
                return jsonify({'token': token}), 200
            else:
                return jsonify({'error': 'Kredensial tidak valid'}), 401
        
        else:
            return jsonify({'error': 'Metode tidak diizinkan'}), 405

    except Exception as e:
        # Tangani kesalahan umum
        return jsonify({'error': str(e)}), 500

def lambda_handler(event, context):
    """Handler untuk Vercel"""
    return handler(event)

# Route utama untuk Vercel
def app_handler(request):
    """Handler utama untuk Vercel"""
    return handler(request)
