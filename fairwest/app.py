from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
from flask_session import Session
from calendar import monthrange
from flask import Response
import csv
from io import StringIO
from zoneinfo import ZoneInfo
import pytz

from zoneinfo import ZoneInfo # For Python 3.9+ if you prefer standard library

# Define your desired local timezone
# Using pytz for now as it's already in your imports and works with older Python versions
local_tz = pytz.timezone('Africa/Johannesburg')


app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Dbase configuration
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Database connection function
def get_db():
    conn = sqlite3.connect("meters.db")
    conn.row_factory = sqlite3.Row  # To access columns by name
    return conn

# Function to close the database connection
def close_db(conn):
    if conn:
        conn.close()

# Function to initialize the database if it doesn't exist
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                unit_number TEXT UNIQUE NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    # Meter readings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS meter_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reading REAL NOT NULL,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # Schedules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                scheduled_date DATETIME NOT NULL,
                is_completed INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        # Create unit number pin code table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS unit_pincode (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                unit_number TEXT UNIQUE NOT NULL,
                pin_code TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        close_db(conn)

# Call init_db when the app starts
with app.app_context():
    init_db()


# Route for the index page
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    user = None
    latest_reading = None
    schedules = []
    readings_count = 0
    upcoming_schedules_count = 0

    try:
        # Get user info
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = dict(cursor.fetchone())

        # Get latest meter reading for dashboard
        cursor.execute("""
            SELECT reading, created_at
            FROM meter_readings
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (session['user_id'],))
        reading_row = cursor.fetchone()

        if reading_row:
            latest_reading = dict(reading_row)
            # Parse as UTC, then convert to local timezone
            created_at_utc = datetime.strptime(latest_reading['created_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            latest_reading['formatted_date'] = created_at_utc.astimezone(local_tz).strftime('%b %d, %Y %I:%M %p')


        # Get total readings count (no change here as it's just a count)
        cursor.execute("SELECT COUNT(*) FROM meter_readings WHERE user_id = ?", (session['user_id'],))
        readings_count = cursor.fetchone()[0]

        # Get upcoming schedules
        cursor.execute("""
            SELECT id, title, description, scheduled_date
            FROM schedules
            WHERE is_completed = 0
            AND scheduled_date >= datetime('now')
            ORDER BY scheduled_date ASC
            LIMIT 5
        """)

        schedule_rows = cursor.fetchall()
        for row in schedule_rows:
            schedule = dict(row)
            # Convert scheduled_date from UTC in DB to local for display
            scheduled_date_utc = datetime.strptime(schedule['scheduled_date'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            schedule['scheduled_date'] = scheduled_date_utc.astimezone(local_tz)
            schedules.append(schedule)

        # Get count of upcoming schedules for the stats card (no change here)
        cursor.execute("""
            SELECT COUNT(*)
            FROM schedules
            WHERE is_completed = 0
            AND scheduled_date >= datetime('now')
        """)
        upcoming_schedules_count = cursor.fetchone()[0]

    except sqlite3.Error as e:
        flash(f"Error fetching data: {e}", 'danger')
    finally:
        close_db(conn)

    return render_template('index.html',
                           user=user,
                           latest_reading=latest_reading,
                           schedules=schedules,
                           readings_count=readings_count,
                           upcoming_schedules_count=upcoming_schedules_count,
                           now=datetime.now(local_tz)) # Use local_tz for 'now' on the dashboard


# Route for load user page
@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            if user:
                g.user = user['username']
        except sqlite3.Error as e:
            flash(f"Error loading user: {e}", 'danger')
        finally:
            close_db(conn)


# Date and time formatting filter
@app.template_filter('format_date')
def format_date_filter(date, format_string='%b %d'):
    if date is None:
        return ''
    
    # If the date is a string from the DB, parse it as UTC
    if isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d %H:%M:%S')
        # Make the naive datetime object timezone-aware (as UTC)
        date = date.replace(tzinfo=pytz.utc)
    
    # If the date is already a timezone-aware datetime object (e.g., from schedules),
    # ensure it's converted to the local_tz for display.
    # If it's already in local_tz, astimezone does nothing or handles correctly.
    return date.astimezone(local_tz).strftime(format_string)


# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        unit_number = request.form['unit_number']

        if not username or not email or not password or not confirm_password or not unit_number:
            flash('All fields, including Unit Number, are required!', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        conn = get_db()
        cursor = conn.cursor()
        existing_user = None
        try:
            cursor.execute("""
                SELECT * FROM users
                WHERE username = ? OR email = ? OR unit_number = ?
            """, (username, email, unit_number))
            existing_user = cursor.fetchone()
        except sqlite3.Error as e:
            flash(f"Database error checking user: {e}", 'danger')
            close_db(conn)
            return redirect(url_for('register'))

        if existing_user:
            if existing_user['username'] == username:
                flash('Username already exists!', 'danger')
            elif existing_user['email'] == email:
                flash('Email already exists!', 'danger')
            elif existing_user['unit_number'] == unit_number:
                flash('Unit number already registered!', 'danger')
            close_db(conn)
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password, unit_number)
                VALUES (?, ?, ?, ?)
            """, (username, email, hashed_password, unit_number))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            close_db(conn)
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            close_db(conn)
            return redirect(url_for('register'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        user = None
        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
        except sqlite3.Error as e:
            flash(f"Database error during login: {e}", 'danger')
            close_db(conn)
            return redirect(url_for('login'))

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            close_db(conn)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')
            close_db(conn)
            return redirect(url_for('login'))

    return render_template('login.html')


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


#Admin route
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    users = []
    user = None
    try:
        cursor.execute("SELECT id, username, email, unit_number, is_admin, created_at FROM users")
        users_data = cursor.fetchall()

        # Convert SQLite date strings to datetime objects
        users = []
        for u in users_data:
            user_dict = dict(u)
            user_dict['created_at'] = datetime.strptime(user_dict['created_at'], '%Y-%m-%d %H:%M:%S')
            users.append(user_dict)

        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
    except sqlite3.Error as e:
        flash(f"Error fetching users: {e}", 'danger')
    finally:
        close_db(conn)

    return render_template('admin.html', users=users, user=user)


# Schedule route
@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    is_admin = session.get('is_admin', False)

    if request.method == 'POST':
        if not is_admin:
            flash('Only administrators can create schedules', 'danger')
            return redirect(url_for('schedule'))

        title = request.form.get('title')
        description = request.form.get('description', '')
        scheduled_date_str = request.form.get('scheduled_date')

        if not title or not scheduled_date_str:
            flash('Title and Date are required', 'danger')
            return redirect(url_for('schedule'))

        try:
            scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format', 'danger')
            return redirect(url_for('schedule'))

        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO schedules (user_id, title, description, scheduled_date)
                VALUES (?, ?, ?, ?)
            """, (session['user_id'], title, description, scheduled_date))
            conn.commit()
            flash('Schedule added successfully!', 'success')
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Error adding schedule: {str(e)}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('schedule'))

    # GET request handling
    conn = get_db()
    try:
        cursor = conn.cursor()
        # Get both completed and upcoming schedules with creator info
        cursor.execute("""
            SELECT s.id, s.title, s.description, s.scheduled_date, s.is_completed,
                   u.username as creator, s.created_at
            FROM schedules s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.is_completed ASC, s.scheduled_date ASC
        """)

        schedules = []
        now = datetime.now()
        for row in cursor.fetchall():
            schedule = dict(row)
            # Convert string to datetime object if needed
            if isinstance(schedule['scheduled_date'], str):
                schedule['scheduled_date'] = datetime.strptime(
                    schedule['scheduled_date'],
                    '%Y-%m-%d %H:%M:%S'
                    )
            if isinstance(schedule['created_at'], str):
                schedule['created_at'] = datetime.strptime(
                    schedule['created_at'],
                    '%Y-%m-%d %H:%M:%S'
                    )

            # Add status flag
            schedule['is_past'] = schedule['scheduled_date'] < now and not schedule['is_completed']
            schedules.append(schedule)

    except sqlite3.Error as e:
        flash(f"Error fetching schedules: {e}", 'danger')
        schedules = []
    finally:
        conn.close()

    return render_template('schedule.html',
                           schedules=schedules,
                           is_admin=is_admin,
                           now=datetime.now())


# Route for the deleting schedule
@app.route('/delete_schedule/<int:schedule_id>', methods=['POST'])
def delete_schedule(schedule_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    try:
        conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        conn.commit()
        flash('Schedule deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error deleting schedule: {str(e)}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('schedule'))


# Meter route
@app.route('/meter', methods=['GET', 'POST'])
def meter():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            reading = float(request.form['reading'])
            if reading < 0:  # Validation before DB operations
                flash('Meter reading cannot be negative', 'danger')
                return redirect(url_for('meter'))

        except ValueError:
            flash('Invalid reading format', 'danger')
            return redirect(url_for('meter'))

        # Proceed with database operations only if validation passes
        notes = request.form.get('notes', '')
        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO meter_readings (user_id, reading, notes)
                VALUES (?, ?, ?)
            """, (session['user_id'], reading, notes))
            conn.commit()
            flash('Reading saved successfully!', 'success')
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Error saving reading: {e}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('meter'))  # Single return point

    return render_template('meter.html')

# History route
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    formatted_readings = []

    try:
        cursor.execute("""
            SELECT id, reading, notes, created_at
            FROM meter_readings
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (session['user_id'],))

        for row in cursor.fetchall():
            reading = dict(row)
            # Parse as UTC, then convert to local timezone
            created_at_utc = datetime.strptime(reading['created_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            created_at_local = created_at_utc.astimezone(local_tz)

            reading['date'] = created_at_local.strftime('%Y-%m-%d')
            reading['time'] = created_at_local.strftime('%H:%M:%S')
            reading['datetime'] = created_at_local.strftime('%Y-%m-%d %H:%M')
            formatted_readings.append(reading)

    except sqlite3.Error as e:
        flash(f"Error fetching history: {e}", 'danger')
    finally:
        close_db(conn)

    return render_template('history.html', readings=formatted_readings)


# Admin history route
@app.route('/admin/history')
def admin_history():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    all_readings = []

    month = request.args.get('month', type=int)
    year = request.args.get('year', type=int)

    try:
        # Base query to get all readings with user and unit info
        query = """
            SELECT mr.id, mr.reading, mr.notes, mr.created_at,
                   u.username, u.unit_number
            FROM meter_readings mr
            JOIN users u ON mr.user_id = u.id
        """
        params = []
        where_clauses = []

        if month and year:
            # Calculate start and end in local time, then convert to UTC for the query
            start_of_month_local = datetime(year, month, 1, 0, 0, 0, tzinfo=local_tz)
            end_day = monthrange(year, month)[1]
            end_of_month_local = datetime(year, month, end_day, 23, 59, 59, tzinfo=local_tz)

            start_date_utc = start_of_month_local.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')
            end_date_utc = end_of_month_local.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')

            where_clauses.append("mr.created_at BETWEEN ? AND ?")
            params.extend([start_date_utc, end_date_utc])

        # Add WHERE clauses if any
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        # Order by unit number first (numerically if possible), then by creation date
        # This will put units 1-5 first, then others, and then order by date within each unit.
        query += " ORDER BY CAST(u.unit_number AS INTEGER) ASC, mr.created_at DESC"

        cursor.execute(query, params)

        for row in cursor.fetchall():
            reading = dict(row)
            # Parse as UTC, then convert to local timezone for display
            created_at_utc = datetime.strptime(reading['created_at'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
            created_at_local = created_at_utc.astimezone(local_tz)

            reading['formatted_date'] = created_at_local.strftime('%Y-%m-%d %H:%M')
            reading['date'] = created_at_local.strftime('%Y-%m-%d')
            reading['time'] = created_at_local.strftime('%H:%M:%S')
            all_readings.append(reading)

    except sqlite3.Error as e:
        flash(f"Error fetching history: {e}", 'danger')
    finally:
        close_db(conn)

    return render_template('admin_history.html',
                           readings=all_readings,
                           selected_month=month,
                           selected_year=year)


# Schedule completion route
@app.route('/complete_schedule/<int:schedule_id>')
def complete_schedule(schedule_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE schedules
            SET is_completed = 1
            WHERE id = ?
        """, (schedule_id,))
        conn.commit()
        if cursor.rowcount == 0:
            flash('Schedule not found!', 'danger')
        else:
            flash('Schedule marked as completed!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error updating schedule: {e}', 'danger')
    finally:
        close_db(conn)
    return redirect(url_for('schedule'))

# --- Route for Unit Pincode Management ---
@app.route('/unit_pincode', methods=['GET', 'POST'])
def unit_pincode():
    # Ensure only admins can access this page
    if 'user_id' not in session or not session.get('is_admin'):
        flash('🔒 Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        unit_number = request.form.get('unit_number')
        pin_code = request.form.get('pin_code')

        if not unit_number or not pin_code:
            flash('❌ Unit Number and Pin Code are required!', 'danger')
        else:
            try:
                # Check if unit already exists
                cursor.execute("SELECT id FROM unit_pincode WHERE unit_number = ?", (unit_number,))
                if cursor.fetchone():
                    flash(f'⚠️ Unit {unit_number} already has a pincode!', 'warning')
                else:
                    cursor.execute(
                        "INSERT INTO unit_pincode (unit_number, pin_code) VALUES (?, ?)",
                        (unit_number, pin_code)
                    )
                    conn.commit()
                    flash(f'✅ Pincode added for Unit {unit_number}!', 'success')
            except sqlite3.Error as e:
                conn.rollback()
                flash(f'❌ Database error: {str(e)}', 'danger')

    # Fetch existing pincodes (admin-only)
    cursor.execute("SELECT * FROM unit_pincode ORDER BY unit_number")
    unit_pincodes = [dict(row) for row in cursor.fetchall()]
    # DEBUG: Print the fetched data
    print("DEBUG - Unit Pincodes:", unit_pincodes)

    conn.close()

    return render_template('unit_pincode.html', unit_pincodes=unit_pincodes)

# Route for deleting a unit pincode
@app.route('/delete_pincode/<int:pincode_id>', methods=['POST'])
def delete_pincode(pincode_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('🔒 Unauthorized: Admin access required.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    try:
        conn.execute("DELETE FROM unit_pincode WHERE id = ?", (pincode_id,))
        conn.commit()
        flash('🗑️ Pincode deleted!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'❌ Error deleting pincode: {str(e)}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('unit_pincode'))

@app.route('/test_pincodes')
def test_pincodes():
    if 'user_id' not in session or not session.get('is_admin'):
        return "Unauthorized", 403
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='unit_pincode'")
    table_exists = cursor.fetchone()
    
    if not table_exists:
        return "unit_pincode table does not exist", 404
    
    # Get record count
    cursor.execute("SELECT COUNT(*) FROM unit_pincode")
    count = cursor.fetchone()[0]
    
    # Get sample data
    cursor.execute("SELECT * FROM unit_pincode LIMIT 5")
    sample_data = cursor.fetchall()
    
    conn.close()
    
    return {
        "table_exists": True,
        "record_count": count,
        "sample_data": [dict(row) for row in sample_data]
    }

#Dowmload readings
@app.route('/admin/download_readings')
def download_readings():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT mr.created_at as date_time, u.username, u.unit_number, mr.reading, mr.notes
        FROM meter_readings mr
        JOIN users u ON mr.user_id = u.id
        ORDER BY mr.created_at DESC
    ''')
    readings = cursor.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Time', 'Username', 'Unit Number', 'Reading', 'Notes'])

    for row in readings:
        # Parse as UTC, then convert to local timezone
        dt_utc = datetime.strptime(row['date_time'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
        dt_local = dt_utc.astimezone(local_tz)

        writer.writerow([
            dt_local.strftime('%Y-%m-%d'),
            dt_local.strftime('%H:%M:%S'),
            row['username'],
            row['unit_number'],
            row['reading'],
            row['notes'] or ''
        ])

    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=all_meter_readings.csv"}
    )
    


# Command line route to create an admin user
@app.cli.command('create-admin')
def create_admin():
    """Create an admin user via command line"""
    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    unit_number = input("Enter admin unit number: ")

    if not all([username, email, password, unit_number]):
        print("All fields (username, email, password, unit number) are required.")
        return

    conn = get_db()
    cursor = conn.cursor()
    existing_user = None
    try:
        cursor.execute("""
            SELECT * FROM users
            WHERE username = ? OR email = ? OR unit_number = ?
        """, (username, email, unit_number))
        existing_user = cursor.fetchone()
    except sqlite3.Error as e:
        print(f"Database error checking user: {e}")
        close_db(conn)
        return

    if existing_user:
        print("Error: Username, email, or unit number already exists.")
        close_db(conn)
        return

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    try:
        cursor.execute("""
            INSERT INTO users (username, email, password, unit_number, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, hashed_password, unit_number, 1))
        conn.commit()
        print(f"Admin user '{username}' (Unit: {unit_number}) created successfully!")
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Error creating admin user: {e}")
    finally:
        close_db(conn)


@app.context_processor
def inject_now():
    return {'now': datetime.now()}

if __name__ == '__main__':
    # It's good practice to enable logging for development
    import logging
    logging.basicConfig(level=logging.INFO)
    #app.run(debug=False)
    app.run(ssl_context='adhoc')  # Never use debug=True in production
