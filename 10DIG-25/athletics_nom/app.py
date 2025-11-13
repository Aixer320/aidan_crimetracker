import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'secret_key'

def get_db_connection():
    conn = sqlite3.connect('flask_login.db') #add timeout to prevent database lock issues
    conn.row_factory = sqlite3.Row
    return conn

event_limits = {
    '100m': 6,
    '200m': 6,
    '1500m': 2,
    'Shot Put': 6,
    'Discus': 6,
    'Javelin': 2,
    'Triple Jump': 2,
    'Long Jump': 6,
    'High Jump': 4,
    '800m': 2
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    if not os.path.exists('flask_login.db'):
        db = get_db_connection()
        with app.open_resource('schema.sql') as f:
            db.executescript(f.read().decode('utf8'))
        db.commit()
        db.close()
        print('Database created and initialized.')
    else:
        print('Database already exists, skipping initialization.')

@app.route('/')
def index():
    current_year = datetime.now().year
    return render_template('index.html', year=current_year)


@app.route('/register', methods=['GET', 'POST'])
def register():
    global db
    error = None
    if request.method == 'POST':
        student_number = request.form['username']
        password = request.form['password']
        email = request.form['email']
        year_level = request.form['year_level']
        gender = request.form['gender']
        house = request.form['house']

        # Check if email already exists
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()# app.py
        db.close()  # Close the database connection after query

        if existing_user:
            error = 'Email already registered. Please use a different email.'
            db.close()
            return render_template('register.html', error=error)

        # Check email domain before proceeding with registration
        if not email.lower().endswith('@stpauls.qld.edu.au'):
            flash('Invalid Email. Please use your school email (@stpauls.qld.edu.au)', 'error')
            return render_template('register.html', error=error)

        # If email is valid, proceed with registration
        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO users (username, password, email, year_level, gender, house) VALUES (?, ?, ?, ?, ?, ?)',
                (student_number, password, email, year_level, gender, house))
            db.commit()
            db.close()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            error = f"Database error: {str(e)}"
            return render_template('register.html', error=error)
        finally:
            if 'db' in locals():
                db.close()

    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():

    if 'username' in session:
        return redirect(url_for('nominate'))

    if request.method == 'POST':
        # Retrieve the user-provided email and password from the form
        email = request.form['email']
        password = request.form['password']

        # Validate that the email and password fields are not empty
        if not email or not password:
            flash('Email and password are required.', 'error') #With the error, the message will turn red
            return render_template('login.html')

        # Connect to the database to retrieve user information
        db = get_db_connection()
        cursor = db.cursor()

        # Fetch user details by email
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        db.close()  # Always close the database connection after query

        if user is None:
            # If no user is found with the provided email address
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

        # Compare the provided password directly with the stored password
        stored_password = user['password']  # Assuming passwords are stored in plain text
        if password == stored_password:
            # If passwords match, log the user in by storing their session
            session['username'] = user['username']
            session['gender'] = user['gender']
            session['year_level'] = user['year_level']
            session['house'] = user['house']
            flash('Login successful!', 'success')
            return redirect(url_for('nominate'))
        else:
            # If the password is incorrect
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

    # If it's a GET request, simply render the login page
    return render_template('login.html')

@app.route('/nominate', methods=['GET', 'POST'])
@login_required
def nominate():
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (session['username'],))
    user = cursor.fetchone()
    gender = user['gender']
    house = user['house']
    year_level = user['year_level']

    # Get overall event counts for the user's gender/house/year level
    event_counts = {}
    for event in event_limits:
        cursor.execute(
            'SELECT COUNT(*) FROM nominations WHERE event=? AND gender=? AND house=? AND year_level=?',
            (event, gender, house, year_level)
        )
        event_counts[event] = cursor.fetchone()[0]

    # Get user's personal nominations for each event
    user_event_counts = {}
    for event in event_limits:
        cursor.execute(
            'SELECT COUNT(*) FROM nominations WHERE username=? AND event=?',
            (session['username'], event)
        )
        user_event_counts[event] = cursor.fetchone()[0]

    cursor.execute(
        'SELECT nomination_id, event FROM nominations WHERE username=?',
        (session['username'],)
    )
    user_nominations = [{'nomination_id': row['nomination_id'], 'event': row['event']} for row in cursor.fetchall()]

    if request.method == 'POST':
        event = request.form['event']
        # Check if user has already nominated for this event
        if user_event_counts[event] > 0:
            flash(f'You have already nominated for {event}.', 'error')
        elif event_counts[event] < event_limits[event]:
            db.execute(
                'INSERT INTO nominations (username, event, gender, house, year_level) VALUES (?, ?, ?, ?, ?)',
                (session['username'], event, gender, house, year_level)
            )
            db.commit()
            flash(f'Successfully nominated for {event}!', 'success')
            return redirect(url_for('nominate'))
        else:
            flash(f'You cannot nominate for {event} as the limit has been reached.', 'error')
            return redirect(url_for('nominate'))

    db.close()

    return render_template(
        'nominate.html',
        event_limits=event_limits,
        event_counts=event_counts,
        user_nominations=user_nominations,
        user_event_counts=user_event_counts,
        username=session['username'],
        gender=gender,
        year_level=year_level,
        house=house
    )

@app.route('/student_portal')
def student_portal():
    return render_template('student_portal.html')

@app.route('/admin_portal')
def admin_portal():
    return render_template('admin_portal.html')


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    error = None
    occupation_codes = {
        'house_leader': '123',
        'house_captain': '123',
        'sport_captain': '456',
        'head_of_sport': '456'
    }
    admin_types = {
        'house_leader': 'house_admin',
        'house_captain': 'house_admin',
        'sport_captain': 'master_admin',
        'head_of_sport': 'master_admin'
    }

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        occupation = request.form['occupation']
        admin_code = request.form.get('admin_code', '')

        # Make sure house is required for house admins
        if occupation in ['house_leader', 'house_captain']:
            house = request.form.get('house')
            if not house:
                error = 'House is required for house administrators.'
                return render_template('admin_register.html', error=error)
        else:
            house = None

        expected_code = occupation_codes.get(occupation)
        admin_type = admin_types.get(occupation, 'regular')

        if not expected_code or admin_code != expected_code:
            error = 'Invalid admin code for your occupation. Registration denied.'
            return render_template('admin_register.html', error=error)

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM admins WHERE username = ?', (username,))
        existing_admin = cursor.fetchone()
        if existing_admin:
            error = 'Username already registered. Please use a different username.'
            db.close()
            return render_template('admin_register.html', error=error)

        try:
            cursor.execute(
                'INSERT INTO admins (username, password, occupation, admin_type, house) VALUES (?, ?, ?, ?, ?)',
                (username, password, occupation, admin_type, house)
            )
            db.commit()
            flash('Admin registration successful! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        except sqlite3.Error as e:
            error = f"Database error: {str(e)}"
            return render_template('admin_register.html', error=error)
        finally:
            if 'db' in locals():
                db.close()

    return render_template('admin_register.html', error=error)

# app.py
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM admins WHERE username = ?', (username,))
        admin = cursor.fetchone()
        db.close()

        if admin and admin['password'] == password:
            session['username'] = admin['username']
            session['admin_type'] = admin['admin_type']

            if admin['admin_type'] == 'house_admin':
                if admin['house'] is None:
                    error = 'House admin account not properly configured.'
                    return render_template('admin_login.html', error=error)

                session['house'] = admin['house']
                return redirect(url_for('view_house_nominations'))
            elif admin['admin_type'] == 'master_admin':
                return redirect(url_for('master_nominations'))
            else:
                return redirect(url_for('admin_portal'))
        else:
            error = 'Invalid username or password.'

    return render_template('admin_login.html', error=error)

@app.route('/master_nominations')
def master_nominations():
    return render_template('master_nominations.html')

def extract_house_from_admin(admin):
    # Implement logic to extract house, e.g. from occupation or another field
    # Example if occupation is "house_leader_Scudo":
    for house in ['Scudo', 'Boek', 'Taja', 'Mitre', 'Gladius']:
        if house in admin['occupation']:
            return house
    return None

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/remove_nomination/<int:nomination_id>', methods=['POST'])
@login_required
def remove_nomination(nomination_id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute('DELETE FROM nominations WHERE nomination_id = ? AND username = ?', (nomination_id, session['username']))
    db.commit()
    db.close()
    flash('Nomination removed successfully.', 'success')
    return redirect(url_for('nominate'))

@app.before_request
def check_admin_session():
    if 'username' in session and request.endpoint == 'admin_login':
        admin_type = session.get('admin_type')
        if admin_type == 'house_admin':
            return redirect(url_for('view_house_nominations'))
        elif admin_type == 'master_admin':
            return redirect(url_for('master_nominations'))
        return redirect(url_for('admin_portal'))

@app.route('/view_house_nominations')
def view_house_nominations():
    if 'username' not in session:
        return redirect(url_for('admin_login'))

    if 'house' not in session:
        return redirect(url_for('admin_login'))

    house = session['house']
    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute('''
                   SELECT DISTINCT year_level, gender
                   FROM nominations
                   WHERE house = ?
                   ORDER BY year_level, gender
                   ''', (house,))
    groups = cursor.fetchall()

    nomination_stats = {}
    for group in groups:
        year = group['year_level']
        gender = group['gender']

        cursor.execute('''
                       SELECT event, COUNT(*) as count
                       FROM nominations
                       WHERE house = ? AND year_level = ? AND gender = ?
                       GROUP BY event
                       ''', (house, year, gender))
        events = cursor.fetchall()

        total_events = len(events)
        complete_events = len([e for e in events if e['count'] >= 6])
        progress = (complete_events / total_events * 100) if total_events > 0 else 0

        nomination_stats[f"{year}_{gender}"] = {
            'events': events,
            'progress': progress,
            'complete': complete_events,
            'total': total_events
        }

    db.close()
    return render_template('view_house_nominations.html',
                           house=house,
                           nomination_stats=nomination_stats)

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        init_db()
    app.run(port=5002, debug=True)