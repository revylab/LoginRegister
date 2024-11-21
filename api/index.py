from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import jwt
import datetime
import json

load_dotenv()

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
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

def verify_token(token):
    """Verify JWT Token"""
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def handler(request_data):
    """Main handler for serverless function"""
    method = request_data.get('method', '')
    
    if method == 'POST':
        # Registrasi User
        data = json.loads(request_data.get('body', '{}'))
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Username dan password diperlukan'})
            }
        
        existing_user = users_collection.find_one({'username': username})
        if existing_user:
            return {
                'statusCode': 409,
                'body': json.dumps({'error': 'Username sudah terdaftar'})
            }
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {
            'username': username,
            'password': hashed_password
        }
        
        result = users_collection.insert_one(user_data)
        token = generate_token(result.inserted_id)
        
        return {
            'statusCode': 201,
            'body': json.dumps({'token': token})
        }
    
    elif method == 'GET':
        # Login User
        data = json.loads(request_data.get('body', '{}'))
        username = data.get('username')
        password = data.get('password')
        
        user = users_collection.find_one({'username': username})
        if user and bcrypt.check_password_hash(user['password'], password):
            token = generate_token(user['_id'])
            return {
                'statusCode': 200,
                'body': json.dumps({'token': token})
            }
        else:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Kredensial tidak valid'})
            }
    
    return {
        'statusCode': 405,
        'body': json.dumps({'error': 'Metode tidak diizinkan'})
    }

def lambda_handler(event, context):
    """AWS Lambda/Vercel Handler"""
    return handler(event)
