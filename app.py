from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Set database file path dynamically relative to the script directory
script_dir = Path(__file__).parent.absolute()
database_file = script_dir / "database.db"

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{database_file}"
db = SQLAlchemy(app)

# Print DB file path on startup
print("Using database file:", database_file)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

# ----------- Decorators -------------

def professor_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'professor':
            return abort(403)
        return f(*args, **kwargs)
    return decorated

# ----------- Routes -------------

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        role = request.form['role']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for('register'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' registered successfully.", "success")

        print(f"New user registered: {username}")
        print("User stored in DB file:", database_file)

        return redirect(url_for('login'))

    return render_template('register.html', title="Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))

        flash("Invalid credentials.", "error")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'professor':
        tiles = [
            {'title': 'My Courses', 'text': 'Create and manage course content.', 'url': '#'},
            {'title': 'Gradebook', 'text': 'Enter and review student grades.', 'url': '#'},
            {'title': 'User Management', 'text': 'Manage users and access control.', 'url': url_for('admin')}
        ]
    else:
        tiles = [
            {'title': 'Enrolled Courses', 'text': 'See course materials and announcements.', 'url': '#'},
            {'title': 'My Grades', 'text': 'Track your performance across classes.', 'url': '#'}
        ]

    return render_template('dashboard.html', username=session['username'], role=session['role'], tiles=tiles)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------- Admin Routes -------------

@app.route('/admin')
@professor_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@professor_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        if user.id == session['user_id']:
            flash("You cannot delete yourself.", "error")
            return redirect(url_for('admin'))

        db.session.delete(user)
        db.session.commit()
        flash(f"Deleted user {user.username}", "success")
    else:
        flash("User not found", "error")
    return redirect(url_for('admin'))

@app.route('/admin/add_user', methods=['GET', 'POST'])
@professor_required
def add_user():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for('add_user'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for('add_user'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' added successfully.", "success")
        return redirect(url_for('admin'))

    return render_template('add_edit_user.html', action="Add", user=None)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@professor_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form.get('password')  # may be empty
        role = request.form['role']

        if not username:
            flash("Username is required.", "error")
            return redirect(url_for('edit_user', user_id=user_id))

        if username != user.username and User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for('edit_user', user_id=user_id))

        user.username = username
        user.role = role

        if password:
            user.set_password(password)

        db.session.commit()
        flash(f"User '{username}' updated successfully.", "success")
        return redirect(url_for('admin'))

    return render_template('add_edit_user.html', action="Edit", user=user)

# ----------- Run App -------------

if __name__ == '__main__':
    app.run(debug=True)
