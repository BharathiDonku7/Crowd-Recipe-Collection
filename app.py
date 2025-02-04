from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

#Configure MySQL Database (Using MySQL Community Server)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root1234@127.0.0.1/capstone'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix Session Handling Issues
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'

#  Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect if a user is not logged in

#  Define the User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

#  User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#  Home Route
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html', user=current_user)

# Signup Route with AJAX Support
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not email or not password:
        return jsonify({'status': 'error', 'message': 'All fields are required!'})

    # Check if email or username already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'status': 'error', 'message': 'Email already exists!'})

    if User.query.filter_by(username=username).first():
        return jsonify({'status': 'error', 'message': 'Username already exists!'})

    # Hash the password and save the user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Automatically log in the user after signup
    login_user(new_user, remember=True)
    session['user_id'] = new_user.id

    return jsonify({'status': 'success', 'message': 'Signup details saved successfully'})

#  Login Route with AJAX Support
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user, remember=True)
        session['user_id'] = user.id
        return jsonify({'status': 'success', 'message': 'Login successful', 'redirect': url_for('dashboard')})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid username or password'})

#  Dashboard Route (Protected)
@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome, {current_user.username}! <a href='/logout'>Logout</a>"

#  Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))  # Redirect to the home page

#  Run Flask App
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
