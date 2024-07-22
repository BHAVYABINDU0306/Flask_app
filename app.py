from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Import sqlite3 to use for direct database operations

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Helper function to check password criteria
def is_valid_password(password):
    if (len(password) >= 8 and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        password[-1].isdigit()):
        return True
    return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        if not is_valid_password(password):
            flash('Password does not meet criteria!')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists!')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('thankyou.html')

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return render_template('secretPage.html')
        else:
            flash('Incorrect email or password')
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/initialize_db')
def initialize_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create table if it does not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    conn.commit()

    # Insert sample data
    cursor.execute('''
        INSERT INTO user (first_name, last_name, email, password)
        VALUES (?, ?, ?, ?);
    ''', ('Mary', 'Jane', 'mary.jane@gmail.com', 'maryjane12345'))
    conn.commit()

    # Query data to show
    cursor.execute('SELECT * FROM user;')
    rows = cursor.fetchall()
    conn.close()

    return f'<pre>{rows}</pre>'

if __name__ == '__main__':
    app.run(debug=True)
