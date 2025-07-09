from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Enter your MySQL password here
app.config['MYSQL_DB'] = 'tyler'
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'static/images/profiles'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

mysql = MySQL(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username/password!', 'danger')
    
    return render_template('login.html')

@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        if account:
            flash('Account already exists!', 'danger')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'danger')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!', 'danger')
        elif not username or not password or not email:
            flash('Please fill out the form!', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)', 
                          (username, email, hashed_password))
            mysql.connection.commit()
            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard/')
def dashboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM employees WHERE user_id = %s', (session['id'],))
        employees = cursor.fetchall()
        return render_template('dashboard.html', username=session['username'], employees=employees)
    return redirect(url_for('login'))

@app.route('/add_employee/', methods=['GET', 'POST'])
def add_employee():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        employee_id = request.form['employee_id']
        position = request.form['position']
        department = request.form['department']
        email = request.form['email']
        contact_number = request.form['contact_number']
        address = request.form['address']
        date_of_birth = request.form['date_of_birth']
        date_hired = request.form['date_hired']
        employment_status = request.form['employment_status']
        
        # Handle file upload
        profile_picture = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{employee_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_picture = filename
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
            INSERT INTO employees 
            (user_id, name, employee_id, position, department, email, contact_number, 
             address, date_of_birth, date_hired, employment_status, profile_picture)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (session['id'], name, employee_id, position, department, email, contact_number, 
              address, date_of_birth, date_hired, employment_status, profile_picture))
        mysql.connection.commit()
        flash('Employee added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_employee.html')

@app.route('/edit_employee/<int:employee_id>', methods=['GET', 'POST'])
def edit_employee(employee_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        name = request.form['name']
        position = request.form['position']
        department = request.form['department']
        email = request.form['email']
        contact_number = request.form['contact_number']
        address = request.form['address']
        date_of_birth = request.form['date_of_birth']
        date_hired = request.form['date_hired']
        employment_status = request.form['employment_status']
        
        # Handle file upload
        profile_picture = request.form.get('existing_profile_picture')
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{employee_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_picture = filename
        
        cursor.execute('''
            UPDATE employees SET 
            name = %s, position = %s, department = %s, email = %s, 
            contact_number = %s, address = %s, date_of_birth = %s, 
            date_hired = %s, employment_status = %s, profile_picture = %s
            WHERE id = %s AND user_id = %s
        ''', (name, position, department, email, contact_number, address, 
              date_of_birth, date_hired, employment_status, profile_picture, 
              employee_id, session['id']))
        mysql.connection.commit()
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    cursor.execute('SELECT * FROM employees WHERE id = %s AND user_id = %s', (employee_id, session['id']))
    employee = cursor.fetchone()
    
    if employee:
        return render_template('edit_employee.html', employee=employee)
    else:
        flash('Employee not found!', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/delete_employee/<int:employee_id>', methods=['POST'])
def delete_employee(employee_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT profile_picture FROM employees WHERE id = %s AND user_id = %s', (employee_id, session['id']))
    employee = cursor.fetchone()
    
    if employee:
        # Delete profile picture if exists
        if employee['profile_picture']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], employee['profile_picture']))
            except:
                pass
        
        cursor.execute('DELETE FROM employees WHERE id = %s AND user_id = %s', (employee_id, session['id']))
        mysql.connection.commit()
        flash('Employee deleted successfully!', 'success')
    else:
        flash('Employee not found!', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)