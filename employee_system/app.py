from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

# Helper functions
def log_activity(user_id, activity):
    """Log user activities"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO activity_log (user_id, activity, ip_address, user_agent)
            VALUES (%s, %s, %s, %s)
        """, (user_id, activity, ip, user_agent))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f"Error logging activity: {str(e)}")
    finally:
        cur.close()

def validate_password(password):
    """Enforce password policy"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit"
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"
    return True, ""

# Decorators for access control
def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function_login(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function_login

def admin_required(f):
    """Require admin role"""
    @wraps(f)
    def decorated_function_admin(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('Admin access required for this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function_admin

def manager_required(f):
    """Require manager or admin role"""
    @wraps(f)
    def decorated_function_manager(*args, **kwargs):
        if 'role' not in session or session['role'] not in ['admin', 'manager']:
            flash('Manager or Admin access required for this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function_manager

def employee_required(f):
    """Require any authenticated user"""
    @wraps(f)
    def decorated_function_employee(*args, **kwargs):
        if 'role' not in session or session['role'] not in ['admin', 'manager', 'employee']:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function_employee

@app.before_request
def before_request():
    """Set session to permanent and check for timeout"""
    session.permanent = True
    app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME
    if 'last_activity' in session:
        last_activity = session['last_activity']
        if datetime.now() - datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S') > Config.PERMANENT_SESSION_LIFETIME:
            session.clear()
            flash('Your session has timed out. Please log in again.', 'info')
            return redirect(url_for('login'))
    session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        requested_role = request.form.get('role')
        
        if not all([username, password, requested_role]):
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
            
        try:
            cur = mysql.connection.cursor()
            
            # Get user from database
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user and check_password_hash(user['password'], password):
                # Verify role
                if user['role'] != requested_role:
                    flash('Invalid role selected', 'danger')
                    return redirect(url_for('login'))
                
                # Login successful
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['employee_id'] = user.get('employee_id')
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
                
        except Exception as e:
            flash('An error occurred during login', 'danger')
            app.logger.error(f"Login error: {str(e)}")
        finally:
            if 'cur' in locals():
                cur.close()
    
    return render_template('login.html', show_signup=True)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        
        # Validate inputs
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        valid, msg = validate_password(password)
        if not valid:
            flash(msg, 'danger')
            return redirect(url_for('signup'))
        
        # Hash password with modern method
        hashed_password = generate_password_hash(password, method='scrypt')
        
        cur = mysql.connection.cursor()
        try:
            # Check if username exists
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))
            
            # Create new user
            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (%s, %s, %s)
            """, (username, hashed_password, role))
            mysql.connection.commit()
            
            flash('Account created successfully! Please login', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            flash('Error creating account', 'danger')
            app.logger.error(f"Signup error: {str(e)}")
        finally:
            cur.close()
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], "Logged out")
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    
    # Common stats for all roles
    cur.execute("SELECT COUNT(*) FROM employees WHERE status = 'active'")
    active_employees = cur.fetchone()['COUNT(*)']
    
    # Role-specific stats
    if session['role'] in ['admin', 'manager']:
        cur.execute("SELECT COUNT(*) FROM leave_requests WHERE status = 'pending'")
        pending_requests = cur.fetchone()['COUNT(*)']
    else:
        pending_requests = None
    
    # Unread notifications count
    if session['employee_id']:
        cur.execute("""
            SELECT COUNT(*) FROM notifications 
            WHERE employee_id = %s AND is_read = FALSE
        """, (session['employee_id'],))
        unread_notifications = cur.fetchone()['COUNT(*)']
    else:
        unread_notifications = 0
    
    # Recent notifications
    if session['employee_id']:
        cur.execute("""
            SELECT * FROM notifications 
            WHERE employee_id = %s 
            ORDER BY created_at DESC 
            LIMIT 5
        """, (session['employee_id'],))
        recent_notifications = cur.fetchall()
    else:
        recent_notifications = []
    
    cur.close()
    
    return render_template('dashboard.html', 
                         active_employees=active_employees,
                         pending_requests=pending_requests,
                         unread_notifications=unread_notifications,
                         recent_notifications=recent_notifications,
                         current_role=session['role'])

# Employee CRUD Operations
@app.route('/employees')
@login_required
def employees():
    cur = mysql.connection.cursor()
    
    if session['role'] == 'admin':
        cur.execute("SELECT * FROM employees ORDER BY last_name, first_name")
    else:
        # Managers only see employees in their department
        cur.execute("""
            SELECT e.* FROM employees e
            JOIN users u ON e.id = u.employee_id
            WHERE e.department = (
                SELECT department FROM employees WHERE id = %s
            )
            ORDER BY e.last_name, e.first_name
        """, (session['employee_id'],))
    
    employees = cur.fetchall()
    cur.close()
    return render_template('employees.html', employees=employees)

@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
@admin_required
def add_employee():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        department = request.form.get('department')
        position = request.form.get('position')
        hire_date = request.form.get('hire_date')
        salary = request.form.get('salary')
        role = request.form.get('role')
        
        # Validate role
        if role not in ['employee', 'manager']:
            flash('Invalid role specified', 'danger')
            return redirect(url_for('add_employee'))
        
        cur = mysql.connection.cursor()
        try:
            # Add employee
            cur.execute("""
                INSERT INTO employees (first_name, last_name, email, phone, department, position, hire_date, salary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, email, phone, department, position, hire_date, salary))
            mysql.connection.commit()
            
            # Create user account
            employee_id = cur.lastrowid
            username = email.split('@')[0]
            password = generate_password_hash('password123', method='scrypt')  # Default password
            
            cur.execute("""
                INSERT INTO users (employee_id, username, password, role)
                VALUES (%s, %s, %s, %s)
            """, (employee_id, username, password, role))
            mysql.connection.commit()
            
            log_activity(session['user_id'], f"Added new employee: {first_name} {last_name}")
            flash('Employee added successfully!', 'success')
            return redirect(url_for('list_employees'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error adding employee: {str(e)}', 'danger')
        finally:
            cur.close()
    
    return render_template('add_employee.html')

@app.route('/edit_employee/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_employee(id):
    cur = mysql.connection.cursor()
    
    # Check permissions
    if session['role'] not in ['admin', 'manager']:
        abort(403)
    
    if session['role'] == 'manager':
        # Managers can only edit employees in their department
        cur.execute("""
            SELECT e.* FROM employees e
            WHERE e.id = %s AND e.department = (
                SELECT department FROM employees WHERE id = %s
            )
        """, (id, session['employee_id']))
        employee = cur.fetchone()
        if not employee:
            cur.close()
            flash('You can only edit employees in your department', 'danger')
            return redirect(url_for('list_employees'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        department = request.form.get('department')
        position = request.form.get('position')
        hire_date = request.form.get('hire_date')
        salary = request.form.get('salary')
        status = request.form.get('status')
        
        try:
            cur.execute("""
                UPDATE employees 
                SET first_name=%s, last_name=%s, email=%s, phone=%s, department=%s, 
                    position=%s, hire_date=%s, salary=%s, status=%s
                WHERE id=%s
            """, (first_name, last_name, email, phone, department, position, hire_date, salary, status, id))
            mysql.connection.commit()
            
            log_activity(session['user_id'], f"Updated employee: {first_name} {last_name}")
            flash('Employee updated successfully!', 'success')
            return redirect(url_for('list_employees'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating employee: {str(e)}', 'danger')
    
    # Get employee data
    cur.execute("SELECT * FROM employees WHERE id = %s", (id,))
    employee = cur.fetchone()
    cur.close()
    
    if not employee:
        flash('Employee not found', 'danger')
        return redirect(url_for('list_employees'))
    
    return render_template('edit_employee.html', employee=employee)

@app.route('/delete_employee/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_employee(id):
    cur = mysql.connection.cursor()
    try:
        # Soft delete (mark as inactive)
        cur.execute("UPDATE employees SET status = 'inactive' WHERE id = %s", (id,))
        mysql.connection.commit()
        
        log_activity(session['user_id'], f"Marked employee {id} as inactive")
        flash('Employee marked as inactive', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting employee: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('list_employees'))

# Notifications
@app.route('/notifications')
@login_required
def view_notifications():
    if not session.get('employee_id'):
        flash('No employee profile associated with your account', 'warning')
        return redirect(url_for('dashboard'))
    
    cur = mysql.connection.cursor()
    
    # Get all notifications
    cur.execute("""
        SELECT n.*, e.first_name, e.last_name
        FROM notifications n
        JOIN employees e ON n.employee_id = e.id
        WHERE n.employee_id = %s
        ORDER BY n.created_at DESC
    """, (session['employee_id'],))
    notifications = cur.fetchall()
    
    # Mark all as read
    cur.execute("""
        UPDATE notifications 
        SET is_read = TRUE 
        WHERE employee_id = %s AND is_read = FALSE
    """, (session['employee_id'],))
    mysql.connection.commit()
    
    cur.close()
    return render_template('notifications.html', notifications=notifications)

@app.route('/send_notification', methods=['GET', 'POST'])
@login_required
def send_notification():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        title = request.form.get('title')
        message = request.form.get('message')
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO notifications (employee_id, title, message)
                VALUES (%s, %s, %s)
            """, (employee_id, title, message))
            mysql.connection.commit()
            
            log_activity(session['user_id'], f"Sent notification to employee {employee_id}")
            flash('Notification sent successfully!', 'success')
            return redirect(url_for('view_notifications'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error sending notification: {str(e)}', 'danger')
        finally:
            cur.close()
    
    # Get list of employees to send to
    cur = mysql.connection.cursor()
    if session['role'] == 'admin':
        cur.execute("SELECT id, first_name, last_name FROM employees WHERE status = 'active'")
    else:
        # Managers can only send to their department
        cur.execute("""
            SELECT e.id, e.first_name, e.last_name 
            FROM employees e
            JOIN users u ON e.id = u.employee_id
            WHERE e.status = 'active' AND e.department = (
                SELECT department FROM employees WHERE id = %s
            ) AND e.id != %s
        """, (session['employee_id'], session['employee_id']))
    
    employees = cur.fetchall()
    cur.close()
    
    return render_template('send_notification.html', employees=employees)

# Leave Management
@app.route('/leave_requests')
@login_required
def view_leave_requests():
    cur = mysql.connection.cursor()
    
    if session['role'] in ['admin', 'manager', 'employee']:
        # Admins/managers see all leave requests
        cur.execute("""
            SELECT lr.*, e.first_name, e.last_name, e.department
            FROM leave_requests lr
            JOIN employees e ON lr.employee_id = e.id
            ORDER BY lr.status, lr.created_at DESC
        """)
    else:
        # Employees only see their own leave requests
        cur.execute("""
            SELECT * FROM leave_requests
            WHERE employee_id = %s
            ORDER BY status, created_at DESC
        """, (session['employee_id'],))
    
    requests = cur.fetchall()
    cur.close()
    return render_template('leave_requests.html', requests=requests)

@app.route('/request_leave', methods=['POST'])
@login_required
@employee_required
def request_leave():
    if not session.get('employee_id'):
        flash('No employee profile associated with your account', 'danger')
        return redirect(url_for('dashboard'))
    
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    reason = request.form.get('reason')
    
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO leave_requests (employee_id, start_date, end_date, reason)
            VALUES (%s, %s, %s, %s)
        """, (session['employee_id'], start_date, end_date, reason))
        mysql.connection.commit()
        
        log_activity(session['user_id'], "Submitted leave request")
        flash('Leave request submitted successfully!', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error submitting leave request: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('view_leave_requests'))

@app.route('/approve_leave/<int:id>')
@login_required
@manager_required
def approve_leave(id):
    cur = mysql.connection.cursor()
    try:
        # Update leave request status
        cur.execute("UPDATE leave_requests SET status = 'approved' WHERE id = %s", (id,))
        
        # Get employee details for notification
        cur.execute("""
            SELECT lr.employee_id, e.first_name, e.last_name, e.email
            FROM leave_requests lr
            JOIN employees e ON lr.employee_id = e.id
            WHERE lr.id = %s
        """, (id,))
        request_data = cur.fetchone()
        
        # Send notification to employee
        cur.execute("""
            INSERT INTO notifications (employee_id, title, message)
            VALUES (%s, %s, %s)
        """, (request_data['employee_id'], 'Leave Request Approved', 
             f'Your leave request from {request_data["first_name"]} {request_data["last_name"]} has been approved.'))
        
        mysql.connection.commit()
        
        log_activity(session['user_id'], f"Approved leave request {id}")
        flash('Leave request approved and notification sent', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error approving leave request: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('view_leave_requests'))

@app.route('/reject_leave/<int:id>')
@login_required
@manager_required
def reject_leave(id):
    cur = mysql.connection.cursor()
    try:
        # Update leave request status
        cur.execute("UPDATE leave_requests SET status = 'rejected' WHERE id = %s", (id,))
        
        # Get employee details for notification
        cur.execute("""
            SELECT lr.employee_id, e.first_name, e.last_name, e.email
            FROM leave_requests lr
            JOIN employees e ON lr.employee_id = e.id
            WHERE lr.id = %s
        """, (id,))
        request_data = cur.fetchone()
        
        # Send notification to employee
        cur.execute("""
            INSERT INTO notifications (employee_id, title, message)
            VALUES (%s, %s, %s)
        """, (request_data['employee_id'], 'Leave Request Rejected', 
             f'Your leave request from {request_data["first_name"]} {request_data["last_name"]} has been rejected.'))
        
        mysql.connection.commit()
        
        log_activity(session['user_id'], f"Rejected leave request {id}")
        flash('Leave request rejected and notification sent', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error rejecting leave request: {str(e)}', 'danger')
    finally:
        cur.close()
    
    return redirect(url_for('view_leave_requests'))

# Employee routes
@app.route('/employees')
def list_employees():
    employees = Employee.query.all()  # Adjust for your database model
    return render_template('employees.html', employees=employees)

# Notifications route
@app.route('/notifications')
def notifications():
    notifications = Notification.query.all()  # Adjust for your model
    return render_template('notifications.html', notifications=notifications)

# Leave requests route
@app.route('/leave_requests')
def leave_requests():
    requests = LeaveRequest.query.all()  # Adjust for your model
    return render_template('leave_requests.html', requests=requests)

if __name__ == '__main__':
    app.run(debug=True)