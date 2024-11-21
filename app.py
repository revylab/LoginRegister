from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
bcrypt = Bcrypt(app)

# Koneksi MongoDB Atlas
client = MongoClient(os.getenv('MONGO_URI'))
db = client.userdb
users_collection = db.users

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Cek user di database
        user = users_collection.find_one({'username': username})
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            flash('Login gagal. Periksa username dan password.')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Cek apakah username sudah ada
        existing_user = users_collection.find_one({'username': username})
        
        if existing_user:
            flash('Username sudah terdaftar!')
            return redirect('/register')
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Simpan user baru
        users_collection.insert_one({
            'username': username,
            'password': hashed_password
        })
        
        flash('Registrasi berhasil!')
        return redirect('/login')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
