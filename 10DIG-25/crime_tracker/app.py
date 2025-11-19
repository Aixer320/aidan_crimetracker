import os
import sqlite3
import csv
import json
import logging
import re
import requests
from datetime import date, datetime
from typing import List, Dict, Any, Optional

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Import config first
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# UTILITY FUNCTIONS (from utils.py)
# ============================================================================

def normalize_text(text: str) -> str:
    """Standardize text for consistent comparison."""
    if not text:
        return ''
    return text.strip().lower()


def validate_qld_coordinates(lat: float, lng: float) -> bool:
    """Check if coordinates are within Queensland bounds."""
    try:
        lat = float(lat)
        lng = float(lng)
        return (config.QLD_BOUNDS['lat_min'] <= lat <= config.QLD_BOUNDS['lat_max'] and
                config.QLD_BOUNDS['lng_min'] <= lng <= config.QLD_BOUNDS['lng_max'])
    except (TypeError, ValueError):
        return False


def parse_coordinate(value) -> Optional[float]:
    """Parse a value to float, return None if invalid."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def validate_crime_type(crime_type: str) -> bool:
    """Check if crime_type is in the allowed whitelist."""
    return crime_type in config.ALLOWED_CRIME_TYPES


def parse_date(date_string: str, formats=None) -> Optional[str]:
    """
    Parse date string to ISO format (YYYY-MM-DD).
    Returns None if parsing fails.
    """
    if not date_string:
        return None

    date_string = str(date_string).strip()
    if not date_string:
        return None

    if not formats:
        formats = [
            "%Y-%m-%d",
            "%d %b %Y",
            "%d %B %Y",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%d-%m-%Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S"
        ]

    # Try fromisoformat first
    try:
        dt = datetime.fromisoformat(date_string)
        return dt.date().isoformat()
    except Exception:
        pass

    # Try each format
    for fmt in formats:
        try:
            dt = datetime.strptime(date_string, fmt)
            return dt.date().isoformat()
        except Exception:
            continue

    # If all parsing fails, return None
    return None


def validate_password(password: str) -> tuple[bool, Optional[str]]:
    """
    Validate password strength.
    Requirements:
    - At least 8 characters
    - Must contain uppercase letter
    - Must contain lowercase letter
    - Must contain number

    Returns (is_valid, error_message)
    """
    if not password or len(password) < 8:
        return False, 'Password must be at least 8 characters long.'

    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'

    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'

    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'

    return True, None


def validate_username(username: str) -> tuple[bool, Optional[str]]:
    """
    Validate username format.
    Returns (is_valid, error_message)
    """
    username = (username or '').strip()
    if not username or len(username) < 3:
        return False, 'Username must be at least 3 characters long.'
    if len(username) > 50:
        return False, 'Username must be at most 50 characters long.'
    # Allow alphanumeric, underscore, hyphen
    if not all(c.isalnum() or c in '_-' for c in username):
        return False, 'Username can only contain letters, numbers, underscore, and hyphen.'
    return True, None


def validate_comment(comment: str, max_words: int) -> tuple[bool, Optional[str]]:
    """
    Validate comment length (in words).
    Returns (is_valid, error_message)
    """
    if not comment:
        return False, 'Comment cannot be empty.'

    words = [w for w in comment.split() if w]
    if len(words) > max_words:
        return False, f'Comment too long. Maximum {max_words} words allowed.'

    return True, None


# ============================================================================
# DATABASE FUNCTIONS (from database.py)
# ============================================================================

def get_db_connection():
    """
    Get a new database connection with Row factory enabled.
    Connection is automatically closed when exiting the context manager.

    Usage:
        with get_db_connection() as conn:
            rows = conn.execute('SELECT * FROM reports').fetchall()

    Returns:
        sqlite3.Connection: Database connection with Row factory
    """
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database schema and tables."""
    with get_db_connection() as conn:
        # Reports table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                crime_type TEXT NOT NULL,
                crime_time TEXT NOT NULL,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                address TEXT,
                submitted_by TEXT,
                status TEXT DEFAULT 'PENDING',
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                comment TEXT
            )
        ''')

        # Admins table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

        # Users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

        # Settings table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        # Add columns if they don't exist (for upgrades)
        try:
            conn.execute('ALTER TABLE reports ADD COLUMN submitted_by TEXT')
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE reports ADD COLUMN status TEXT DEFAULT 'PENDING'")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute('ALTER TABLE reports ADD COLUMN comment TEXT')
        except sqlite3.OperationalError:
            pass

        # Add database indexes for performance
        conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_submitted_by ON reports(submitted_by)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_reports_submitted_at ON reports(submitted_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')

        # Ensure there is a default last_updated value
        cur = conn.execute("SELECT value FROM settings WHERE key = 'last_updated'")
        row = cur.fetchone()
        if not row:
            conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('last_updated', date('now'))")

        conn.commit()


def get_resolved_suburbs_db_connection():
    """
    Get a new database connection for resolved suburbs with Row factory enabled.

    Returns:
        sqlite3.Connection: Database connection with Row factory
    """
    conn = sqlite3.connect(config.RESOLVED_SUBURBS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_resolved_suburbs_db():
    """Initialize resolved suburbs database schema."""
    with get_resolved_suburbs_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS resolved_suburbs (
                crime_date TEXT NOT NULL,
                crime_type TEXT NOT NULL,
                postcode TEXT NOT NULL,
                suburb TEXT NOT NULL,
                resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (crime_date, crime_type, postcode)
            )
        ''')

        # Add index for faster lookups
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_resolved_lookup 
            ON resolved_suburbs(crime_date, crime_type, postcode)
        ''')

        conn.commit()
        logger.info("Resolved suburbs database initialized")


def get_resolved_suburb(crime_date: str, crime_type: str, postcode: str) -> Optional[str]:
    """
    Get resolved suburb from database for a specific crime.

    Args:
        crime_date: Crime date in ISO format (YYYY-MM-DD)
        crime_type: Type of crime
        postcode: Postcode as string

    Returns:
        Suburb name if found, None otherwise
    """
    try:
        with get_resolved_suburbs_db_connection() as conn:
            row = conn.execute(
                'SELECT suburb FROM resolved_suburbs WHERE crime_date = ? AND crime_type = ? AND postcode = ?',
                (crime_date, crime_type, postcode)
            ).fetchone()
            return row['suburb'] if row else None
    except Exception as e:
        logger.error(f"Error getting resolved suburb: {e}")
        return None


def save_resolved_suburb(crime_date: str, crime_type: str, postcode: str, suburb: str) -> bool:
    """
    Save a resolved suburb to the database.

    Args:
        crime_date: Crime date in ISO format (YYYY-MM-DD)
        crime_type: Type of crime
        postcode: Postcode as string
        suburb: Resolved suburb name

    Returns:
        True if successful, False otherwise
    """
    try:
        with get_resolved_suburbs_db_connection() as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO resolved_suburbs 
                   (crime_date, crime_type, postcode, suburb, resolved_at) 
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                (crime_date, crime_type, postcode, suburb)
            )
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error saving resolved suburb: {e}")
        return False


def batch_save_resolved_suburbs(suburbs_data: List[Dict[str, str]]) -> int:
    """
    Batch save multiple resolved suburbs.

    Args:
        suburbs_data: List of dicts with keys: crime_date, crime_type, postcode, suburb

    Returns:
        Number of suburbs successfully saved
    """
    if not suburbs_data:
        return 0

    saved_count = 0
    try:
        with get_resolved_suburbs_db_connection() as conn:
            for data in suburbs_data:
                try:
                    conn.execute(
                        '''INSERT OR REPLACE INTO resolved_suburbs 
                           (crime_date, crime_type, postcode, suburb, resolved_at) 
                           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                        (data['crime_date'], data['crime_type'], data['postcode'], data['suburb'])
                    )
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Error saving suburb in batch: {e}")
                    continue
            conn.commit()
        logger.info(f"Batch saved {saved_count}/{len(suburbs_data)} resolved suburbs")
    except Exception as e:
        logger.error(f"Error in batch save: {e}")

    return saved_count


def get_setting(key: str, default: str = '') -> str:
    """Get a setting value from the database."""
    with get_db_connection() as conn:
        row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
        return row['value'] if row and row['value'] is not None else default


def set_setting(key: str, value: str) -> None:
    """Set a setting value in the database."""
    with get_db_connection() as conn:
        conn.execute('INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)', (key, value))
        conn.commit()


def bulk_update_status(ids: List[int], new_status: str) -> bool:
    """
    Update status for multiple reports.
    Returns True if successful, False otherwise.
    """
    if not ids or not isinstance(ids, list) or not all(isinstance(id, int) for id in ids):
        logger.warning(f"Invalid ids provided to bulk_update_status: {ids}")
        return False

    try:
        with get_db_connection() as conn:
            placeholders = ','.join(['?'] * len(ids))
            query = f"UPDATE reports SET status = ? WHERE id IN ({placeholders})"
            conn.execute(query, [new_status] + ids)
            conn.commit()
            logger.info(f"Updated {len(ids)} reports to status {new_status}")
        return True
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during bulk_update_status: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during bulk_update_status: {e}")
        return False


def bulk_delete_reports(ids: List[int]) -> bool:
    """
    Delete multiple reports.
    Returns True if successful, False otherwise.
    """
    if not ids or not isinstance(ids, list) or not all(isinstance(id, int) for id in ids):
        logger.warning(f"Invalid ids provided to bulk_delete_reports: {ids}")
        return False

    try:
        with get_db_connection() as conn:
            placeholders = ','.join(['?'] * len(ids))
            query = f"DELETE FROM reports WHERE id IN ({placeholders})"
            conn.execute(query, ids)
            conn.commit()
            logger.info(f"Deleted {len(ids)} reports")
        return True
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during bulk_delete_reports: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during bulk_delete_reports: {e}")
        return False


def get_all_reports(status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all reports, optionally filtered by status."""
    with get_db_connection() as conn:
        if status_filter:
            rows = conn.execute(
                'SELECT * FROM reports WHERE status = ? ORDER BY submitted_at DESC',
                (status_filter,)
            ).fetchall()
        else:
            rows = conn.execute('SELECT * FROM reports ORDER BY submitted_at DESC').fetchall()
        return [dict(row) for row in rows]


def get_admin_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get admin user by username."""
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get regular user by username."""
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        return dict(row) if row else None


def insert_admin(username: str, password_hash: str) -> bool:
    """Insert a new admin user."""
    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)',
                        (username, password_hash))
            conn.commit()
            logger.info(f"New admin user created: {username}")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Admin registration failed: username '{username}' already exists")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during admin insertion: {e}")
        return False


def insert_user(username: str, password_hash: str) -> bool:
    """Insert a new regular user."""
    try:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                        (username, password_hash))
            conn.commit()
            logger.info(f"New user registered: {username}")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"User registration failed: username '{username}' already exists")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during user insertion: {e}")
        return False


def insert_report(crime_type: str, crime_time: str, lat: float, lng: float,
                  address: str, submitted_by: str, status: str, comment: str = '') -> bool:
    """Insert a new crime report."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO reports (crime_type, crime_time, lat, lng, address, submitted_by, status, comment) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (crime_type, crime_time, lat, lng, address, submitted_by, status, comment)
            )
            conn.commit()
            logger.info(f"Crime report submitted by {submitted_by}: {crime_type}")
        return True
    except sqlite3.OperationalError as e:
        logger.error(f"Database operational error during report insertion: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during report insertion: {e}")
        return False


def insert_report_with_id(crime_type: str, crime_time: str, lat: float, lng: float,
                          address: str, submitted_by: str, status: str, comment: str = '') -> Optional[int]:
    """Insert a report and return the inserted row id, or None on failure."""
    try:
        with get_db_connection() as conn:
            cur = conn.execute(
                'INSERT INTO reports (crime_type, crime_time, lat, lng, address, submitted_by, status, comment) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (crime_type, crime_time, lat, lng, address, submitted_by, status, comment)
            )
            conn.commit()
            rid = cur.lastrowid
            logger.info(f"Crime report inserted with id={rid} by {submitted_by}: {crime_type}")
            return int(rid) if rid else None
    except Exception as e:
        logger.error(f"Error inserting report with id return: {e}")
        return None


# ============================================================================
# FLASK APP INITIALIZATION AND ROUTES
# ============================================================================

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Add security headers
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if not session.get('user'):
        flash('User login required.', 'error')
        return redirect(url_for('index'))
    # Pass username and last_updated to template
    last_updated = get_setting(config.SETTING_LAST_UPDATED, '')
    username = session.get('username')
    can_switch = bool(session.get('admin_backup'))
    return render_template('home.html', username=username, last_updated=last_updated, can_switch_to_admin=can_switch)

@app.route('/submit_crime', methods=['POST'])
def submit_crime():
    lat_str = request.form.get('lat', '')
    lng_str = request.form.get('lng', '')
    address = request.form.get('address', '')
    crime_type = request.form.get('crime_type', '')
    crime_time = request.form.get('crime_time', '')
    comment = (request.form.get('comment') or '').strip()
    anonymous = request.form.get('anonymous')

    # Parse coordinates
    lat = parse_coordinate(lat_str)
    lng = parse_coordinate(lng_str)

    # Validate coordinates are present
    if lat is None or lng is None:
        flash('Invalid location.', 'error')
        # Redirect admins back to admin_home, users to home
        if session.get('admin'):
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))

    # Validate coordinates are in Queensland
    if not validate_qld_coordinates(lat, lng):
        flash('Only locations in Queensland are supported.', 'error')
        if session.get('admin'):
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))

    # Validate required fields
    if not crime_type or not crime_time:
        flash('Please fill in all required fields.', 'error')
        if session.get('admin'):
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))

    # Validate crime type is in whitelist
    if not validate_crime_type(crime_type):
        flash('Invalid crime type selected.', 'error')
        if session.get('admin'):
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))

    # Validate comment if "Other/Unsure"
    if crime_type == 'Other/Unsure':
        if not comment:
            flash('Please add a short comment (<= 10 words) for Other/Unsure.', 'error')
            if session.get('admin'):
                return redirect(url_for('admin_home'))
            return redirect(url_for('home'))
        is_valid, error_msg = validate_comment(comment, config.COMMENT_WORD_LIMIT_OTHER_UNSURE)
        if not is_valid:
            flash(error_msg, 'error')
            if session.get('admin'):
                return redirect(url_for('admin_home'))
            return redirect(url_for('home'))

    # Determine submitter - use ANON: prefix to track anonymity while preserving username for stats
    actual_username = session.get('username', 'Unknown')
    submitter = f"ANON:{actual_username}" if anonymous else actual_username

    # Check if admin is submitting - if so, auto-approve
    is_admin = session.get('admin', False)
    admin_submit = request.form.get('admin_submit') == 'true'
    status = config.STATUS_APPROVED if (is_admin and admin_submit) else config.STATUS_PENDING

    # Insert report into database
    success = insert_report(
        crime_type=crime_type,
        crime_time=crime_time,
        lat=lat,
        lng=lng,
        address=address,
        submitted_by=submitter,
        status=status,
        comment=comment
    )

    if success:
        if status == config.STATUS_APPROVED:
            flash('Crime report submitted and auto-approved!')
        else:
            flash('Crime report submitted! Pending admin approval.')
        # Redirect admins to admin_home, users to home
        if is_admin:
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))
    else:
        flash('Failed to submit crime report. Please try again.', 'error')
        if is_admin:
            return redirect(url_for('admin_home'))
        return redirect(url_for('home'))

@app.route('/api/reports')
def api_reports():
    reports = get_all_reports(status_filter=config.STATUS_APPROVED)
    return jsonify(reports)

@app.route('/api/admin_reports')
def api_admin_reports():
    # Only allow if admin is logged in
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    reports = get_all_reports()
    return jsonify(reports)

@app.route('/api/user_stats')
def api_user_stats():
    """Get stats for the current logged-in user."""
    username = session.get('user') or session.get('admin')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401

    with get_db_connection() as conn:
        # Get all reports by this user (including anonymous ones marked with ANON: prefix)
        # Check for both direct submissions and ANON: prefixed submissions
        all_reports = conn.execute(
            'SELECT * FROM reports WHERE submitted_by = ? OR submitted_by = ?',
            (username, f"ANON:{username}")
        ).fetchall()
        all_reports = [dict(row) for row in all_reports]

        # Count by status
        total_crimes = len(all_reports)
        pending = sum(1 for r in all_reports if r['status'] == config.STATUS_PENDING)
        approved = sum(1 for r in all_reports if r['status'] == config.STATUS_APPROVED)

    return jsonify({
        'username': username,
        'total_crimes': total_crimes,
        'pending': pending,
        'approved': approved
    })

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/admin_approve/<int:report_id>', methods=['POST'])
def admin_approve(report_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    success = bulk_update_status([report_id], config.STATUS_APPROVED)
    return jsonify({'success': success})

@app.route('/admin_disapprove/<int:report_id>', methods=['POST'])
def admin_disapprove(report_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    success = bulk_update_status([report_id], config.STATUS_DISAPPROVED)
    return jsonify({'success': success})

@app.route('/admin_delete/<int:report_id>', methods=['POST'])
def admin_delete(report_id):
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    success = bulk_delete_reports([report_id])
    return jsonify({'success': success})

# Bulk actions on reports (approve, disapprove, delete)
@app.route('/admin/bulk_action', methods=['POST'])
def admin_bulk_action():
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403

    # Validate content type
    if not request.is_json:
        logger.warning(f"Bulk action received non-JSON request from {session.get('username')}")
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json(silent=True) or {}
    action = (data.get('action') or '').upper()
    ids = data.get('ids') or []

    # Validate input
    if not isinstance(ids, list) or not ids or not all(isinstance(id, int) for id in ids):
        logger.warning(f"Invalid IDs in bulk action: {ids}")
        return jsonify({'error': 'Invalid IDs provided'}), 400

    # Validate action is one of the allowed actions
    if action == 'APPROVE':
        success = bulk_update_status(ids, config.STATUS_APPROVED)
    elif action == 'DISAPPROVE':
        success = bulk_update_status(ids, config.STATUS_DISAPPROVED)
    elif action == 'DELETE':
        success = bulk_delete_reports(ids)
    else:
        logger.warning(f"Invalid bulk action requested: {action}")
        return jsonify({'error': 'Invalid action'}), 400

    if success:
        logger.info(f"Bulk action '{action}' applied to {len(ids)} reports by {session.get('username')}")
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Operation failed'}), 500

# CSV import to update real crimes JSON
@app.route('/admin/import_csv', methods=['POST'])
def admin_import_csv():
    if not session.get('admin'):
        flash('Admin login required.', 'error')
        return redirect(url_for('index'))

    # Support both single file (csv_file) and multiple files (csv_files)
    files = request.files.getlist('csv_files')
    if not files or len(files) == 0:
        # Fallback to single file for backwards compatibility
        single_file = request.files.get('csv_file')
        if single_file and single_file.filename:
            files = [single_file]
        else:
            flash('Please choose at least one CSV file to import.', 'error')
            return redirect(url_for('admin_home'))

    # Validate file size (50MB limit per file)
    MAX_CSV_SIZE_BYTES = 50 * 1024 * 1024

    # Validate all files first
    for f in files:
        if not f or not f.filename:
            continue
        if f.content_length and f.content_length > MAX_CSV_SIZE_BYTES:
            flash(f'File "{f.filename}" too large. Maximum {MAX_CSV_SIZE_BYTES / (1024*1024):.0f}MB allowed per file.', 'error')
            return redirect(url_for('admin_home'))

    try:
        # Load existing data once
        os.makedirs(config.STATIC_DIR, exist_ok=True)
        existing = []
        if os.path.exists(config.JSON_OUTPUT_PATH):
            try:
                with open(config.JSON_OUTPUT_PATH, 'r', encoding='utf-8') as jf:
                    existing = json.load(jf)
            except Exception:
                existing = []

        # Try to load the update_real_crimes module for postcode generation
        try:
            import update_real_crimes as updater
            try:
                updater._load_poa_bounds()
            except Exception:
                pass
            try:
                updater._load_suburb_bounds()
            except Exception:
                pass
        except Exception:
            updater = None

        # Aggregate stats across all files
        total_imported = 0
        total_duplicates = 0
        total_empty = 0
        processed_files = 0
        failed_files = []

        # Process each CSV file
        for f in files:
            if not f or not f.filename:
                continue

            try:
                content = f.stream.read().decode('utf-8', errors='ignore')

                # Additional safety check on actual content size
                if len(content) > MAX_CSV_SIZE_BYTES:
                    failed_files.append(f"{f.filename}: Content too large")
                    continue

                reader = csv.DictReader(content.splitlines())

                # Process CSV rows - pass current merged data as "existing"
                stats = _process_csv_rows(reader, existing, updater)

                # Update existing data with merged results for next file
                existing = stats['merged']

                # Aggregate stats
                total_imported += stats['imported']
                total_duplicates += stats['duplicates']
                total_empty += stats['empty']
                processed_files += 1

                logger.info(
                    f"Processed file '{f.filename}': "
                    f"{stats['imported']} new, {stats['duplicates']} duplicates, {stats['empty']} empty"
                )

            except Exception as e:
                failed_files.append(f"{f.filename}: {str(e)}")
                logger.error(f"Error processing file '{f.filename}': {str(e)}")
                continue

        # Save merged data from all files
        with open(config.JSON_OUTPUT_PATH, 'w', encoding='utf-8') as jf:
            json.dump(existing, jf, ensure_ascii=False)

        # Update last_updated timestamp
        today = date.today().isoformat()
        set_setting(config.SETTING_LAST_UPDATED, today)

        logger.info(
            f"Batch CSV import completed by {session.get('username')}: "
            f"{processed_files} files processed, {total_imported} new, "
            f"{total_duplicates} duplicates, {total_empty} empty"
        )

        # Build success message
        success_msg = (
            f"Batch import complete: {processed_files} file(s) processed, "
            f"{total_imported} new records, {total_duplicates} duplicates skipped, "
            f"{total_empty} empty rows skipped. Last updated: {today}"
        )

        if failed_files:
            success_msg += f" | Failed files: {', '.join(failed_files)}"
            flash(success_msg, 'warning')
        else:
            flash(success_msg, 'success')

    except ValueError as e:
        logger.error(f"CSV parsing error during batch import by {session.get('username')}: {str(e)}")
        flash(f'CSV parsing error: {str(e)}', 'error')
    except IOError as e:
        logger.error(f"File I/O error during batch CSV import by {session.get('username')}: {str(e)}")
        flash(f'File I/O error: {str(e)}', 'error')
    except Exception as e:
        logger.error(f"Unexpected error during batch CSV import by {session.get('username')}: {str(e)}")
        flash(f'Batch import failed: {str(e)}', 'error')

    return redirect(url_for('admin_home'))


def _process_csv_rows(reader, existing_data, updater_module):
    """
    Process CSV rows, detect duplicates, and merge with existing data.
    Returns stats dict with import counts.

    Only skips records that already exist in existing_data.
    Allows duplicates within the CSV itself to be imported.
    """
    def _pick_field(row, *field_names):
        """Pick first non-empty field from row."""
        for name in field_names:
            if name in row and row[name]:
                return str(row[name]).strip()
        return ''

    def _build_signature(rec):
        """Build canonical signature for duplicate detection.
        Tries: crime_type + iso_date + postcode
        Fallback: crime_type + iso_date + suburb (if postcode missing)
        Returns None if any required core field is missing."""
        ctype = normalize_text(rec.get('crime_type', ''))
        # Prefer iso_date (parsed), but fall back to normalized crime_time
        ctime = rec.get('iso_date') or normalize_text(rec.get('crime_time', ''))
        postcode = normalize_text(rec.get('postcode', ''))
        suburb = normalize_text(rec.get('suburb', ''))

        # Must have crime type and some form of date
        if not ctype or not ctime:
            return None

        # Prefer postcode, fall back to suburb
        location = postcode or suburb

        # Must have location info
        if not location:
            return None

        return f"{ctype}|{ctime}|{location}"

    # Build signature set ONLY from existing data in JSON (don't track CSV rows)
    existing_sigs = set()
    for existing_rec in existing_data:
        sig = _build_signature(existing_rec)
        if sig:
            existing_sigs.add(sig)

    logger.info(f"Loaded {len(existing_data)} existing records, {len(existing_sigs)} unique signatures to check against")

    merged = list(existing_data)
    imported = 0
    duplicates = 0
    empty = 0
    sample_dupes = []  # Track first few duplicates for logging

    for row in reader:
        # Extract fields with fallback names
        lat_str = _pick_field(row, 'lat', 'latitude', 'Lat', 'Latitude', 'LAT', 'y', 'Y')
        lng_str = _pick_field(row, 'lng', 'lon', 'long', 'longitude', 'Longitude', 'LNG', 'x', 'X')
        crime_type = _pick_field(row, 'crime_type', 'Type', 'Offence', 'Offence Type', 'offence', 'category') or 'Crime'
        crime_time = _pick_field(row, 'crime_time', 'Date', 'Offence Date', 'date', 'datetime', 'timestamp')
        address = _pick_field(row, 'address', 'Address')
        suburb = _pick_field(row, 'suburb', 'Suburb', 'Area of Interest', 'locality', 'area')
        postcode = _pick_field(row, 'postcode', 'Postcode', 'Post Code', 'pcode', 'PCODE')

        # Parse coordinates
        lat = parse_coordinate(lat_str)
        lng = parse_coordinate(lng_str)

        # Handle postcode as suburb if present
        if not postcode and suburb and suburb.isdigit() and len(suburb) == 4:
            postcode = suburb
            suburb = ''

        # Parse date to ISO format
        iso_date = parse_date(crime_time)

        # Build record
        rec = {
            'lat': lat,
            'lng': lng,
            'crime_type': crime_type,
            'crime_time': crime_time,
            'iso_date': iso_date,
            'address': address,
            'suburb': suburb,
            'postcode': postcode,
        }

        # Skip if no useful fields
        if not any([rec['lat'], rec['lng'], rec['crime_type'], rec['crime_time'], rec['address'], rec['suburb'], rec['postcode']]):
            empty += 1
            continue

        # Check for duplicates ONLY against existing data
        sig = _build_signature(rec)
        if sig and sig in existing_sigs:
            duplicates += 1
            if len(sample_dupes) < 3:
                sample_dupes.append({
                    'crime_type': rec.get('crime_type'),
                    'crime_time': rec.get('crime_time'),
                    'iso_date': rec.get('iso_date'),
                    'postcode': rec.get('postcode'),
                    'suburb': rec.get('suburb'),
                    'signature': sig
                })
            continue

        # Always add to merged (even if it's a duplicate within the CSV itself)
        merged.append(rec)
        imported += 1

    return {
        'merged': merged,
        'imported': imported,
        'duplicates': duplicates,
        'empty': empty,
        'sample_duplicates': sample_dupes,
    }


# Admin: switch to user interface (clears admin session, sets user session)
@app.route('/admin/switch_to_user', methods=['POST'])
def admin_switch_to_user():
    if not session.get('admin'):
        flash('Admin login required.', 'error')
        return redirect(url_for('index'))
    username = session.get('admin')
    # Clear admin role but remember we came from admin to allow switching back
    session['admin_backup'] = username
    session.pop('admin', None)
    session['username'] = username
    session['user'] = username
    flash('Switched to user view.', 'success')
    return redirect(url_for('home'))

# Switch back to admin view if we previously switched from admin
@app.route('/user/switch_to_admin', methods=['POST'])
def user_switch_to_admin():
    if not session.get('user'):
        flash('User login required.', 'error')
        return redirect(url_for('index'))

    admin_name = session.get('admin_backup')
    if not admin_name:
        flash('Switch back not available.', 'error')
        return redirect(url_for('home'))

    # Validate this admin exists
    admin = get_admin_by_username(admin_name)
    if not admin:
        # Safety: clear backup if stale
        session.pop('admin_backup', None)
        flash('Admin account not found.', 'error')
        return redirect(url_for('home'))

    # Restore admin session, enforce one-role-at-a-time
    session['admin'] = admin_name
    session['username'] = admin_name
    session.pop('user', None)
    session.pop('admin_backup', None)
    flash('Switched to admin view.', 'success')
    return redirect(url_for('admin_home'))

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        access_code = request.form.get('access_code', '')
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm') or ''

        # Validate access code
        if access_code != config.ADMIN_ACCESS_CODE:
            logger.warning(f"Admin registration attempt with invalid access code from {request.remote_addr}")
            flash('Invalid access code.', 'error')
            return render_template('admin_register.html')

        # Validate username format
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('admin_register.html')

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('admin_register.html')

        # Validate passwords match
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('admin_register.html')

        # Try to insert admin
        password_hash = generate_password_hash(password)
        if insert_admin(username, password_hash):
            flash('Admin registered successfully!', 'success')
            return redirect(url_for('admin_login'))
        else:
            logger.warning(f"Admin registration failed: username '{username}' already exists")
            flash('Username already exists.', 'error')
            return render_template('admin_register.html')

    return render_template('admin_register.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin'):
        return redirect(url_for('admin_home'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('admin_login.html')

        admin = get_admin_by_username(username)
        if admin and check_password_hash(admin['password_hash'], password):
            session.pop('user', None)
            session['username'] = username
            session['admin'] = username
            logger.info(f"Admin '{username}' logged in successfully")
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_home'))
        else:
            logger.warning(f"Failed admin login attempt for username '{username}' from {request.remote_addr}")
            flash('Invalid admin username or password.', 'error')

    return render_template('admin_login.html')

# --- Added: User authentication routes ---
@app.route('/user_register', methods=['GET', 'POST'])
def user_register():
    # If already logged in as user, go home
    if session.get('user'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm = request.form.get('confirm') or ''

        # Validate username format
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('user_register.html')

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('user_register.html')

        # Validate passwords match
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('user_register.html')

        # Try to insert user
        password_hash = generate_password_hash(password)
        if insert_user(username, password_hash):
            # Login as regular user; ensure exclusive role
            session.pop('admin', None)
            session['username'] = username
            session['user'] = username
            flash('User registration successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Username already exists.', 'error')
            return render_template('user_register.html')

    return render_template('user_register.html')

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if session.get('user'):
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('user_login.html')

        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.pop('admin', None)
            session['username'] = username
            session['user'] = username
            logger.info(f"User '{username}' logged in successfully")
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            logger.warning(f"Failed user login attempt for username '{username}' from {request.remote_addr}")
            flash('Invalid username or password.', 'error')

    return render_template('user_login.html')

@app.route('/admin_home')
def admin_home():
    if not session.get('admin'):
        flash('Admin login required.', 'error')
        return redirect(url_for('index'))

    last_updated = get_setting(config.SETTING_LAST_UPDATED, '')
    username = session.get('username')
    return render_template('admin_home.html', username=username, last_updated=last_updated)

# Add route to update the "last_updated" date shown to users
@app.route('/admin/update_last_updated', methods=['POST'])
def admin_update_last_updated():
    if not session.get('admin'):
        flash('Admin login required.', 'error')
        return redirect(url_for('index'))

    value = (request.form.get('last_updated') or '').strip()
    if not value:
        flash('Please choose a date.', 'error')
        return redirect(url_for('admin_home'))

    # Validate YYYY-MM-DD format
    try:
        y, m, d = map(int, value.split('-'))
        _ = date(y, m, d)
    except Exception:
        flash('Invalid date format.', 'error')
        return redirect(url_for('admin_home'))

    set_setting(config.SETTING_LAST_UPDATED, value)
    flash('Last updated date saved.', 'success')
    return redirect(url_for('admin_home'))

# Admin: clear the real crimes JSON dataset (empties the static file)
@app.route('/admin/clear_real_crimes', methods=['POST'])
def admin_clear_real_crimes():
    if not session.get('admin'):
        flash('Admin login required.', 'error')
        return redirect(url_for('index'))

    try:
        os.makedirs(config.STATIC_DIR, exist_ok=True)
        with open(config.JSON_OUTPUT_PATH, 'w', encoding='utf-8') as jf:
            json.dump([], jf)
        # Reset last_updated to blank so users notice re-import required
        set_setting(config.SETTING_LAST_UPDATED, '')
        flash('Real crimes dataset cleared. You can now re-import CSVs.', 'success')
    except Exception as e:
        flash(f'Failed to clear dataset: {e}', 'error')

    return redirect(url_for('admin_home'))

# Simple in-memory rate limiter for suburb resolution API
_last_resolve_time = 0
_resolve_lock = None

def _get_resolve_lock():
    """Get or create the lock for rate limiting."""
    global _resolve_lock
    if _resolve_lock is None:
        import threading
        _resolve_lock = threading.Lock()
    return _resolve_lock

@app.route('/api/resolve_suburb', methods=['POST'])
def api_resolve_suburb():
    """
    API endpoint to resolve suburb for a crime record.
    Accepts: { "lat": number, "lng": number }
    Returns: { "suburb": string }
    """
    import time

    data = request.get_json(silent=True) or {}
    lat = data.get('lat')
    lng = data.get('lng')

    if not lat or not lng:
        return jsonify({'error': 'Missing lat/lng'}), 400

    try:
        lat = float(lat)
        lng = float(lng)

        if not validate_qld_coordinates(lat, lng):
            return jsonify({'suburb': ''}), 200

        # Server-side rate limiting: ensure at least 1 second between requests
        global _last_resolve_time
        lock = _get_resolve_lock()

        with lock:
            current_time = time.time()
            time_since_last = current_time - _last_resolve_time
            if time_since_last < 1.0:
                # Wait to respect rate limit
                time.sleep(1.0 - time_since_last)
            _last_resolve_time = time.time()

        # Use Nominatim API to resolve suburb
        url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}&zoom=14&addressdetails=1'
        headers = {'Accept-Language': 'en', 'User-Agent': 'CrimeTracker/1.0'}

        # Disable SSL verification to handle self-signed certificates in corporate environments
        # Also add warnings filter to suppress InsecureRequestWarning
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)

        response = requests.get(url, headers=headers, timeout=10, verify=False)

        # Check for rate limiting response
        if response.status_code == 429:
            logger.warning(f"Rate limited by Nominatim API")
            return jsonify({'error': 'Rate limited'}), 429

        if response.ok:
            result_data = response.json()
            if result_data and result_data.get('address'):
                addr = result_data['address']
                suburb = addr.get('suburb') or addr.get('neighbourhood') or addr.get('locality') or addr.get('village') or addr.get('town') or addr.get('city_district') or ''
                city = addr.get('city') or addr.get('town') or addr.get('village') or addr.get('county') or addr.get('region') or ''
                pretty = suburb + (f', {city}' if suburb and city else city)
                return jsonify({'suburb': pretty}), 200

        return jsonify({'suburb': ''}), 200
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout resolving suburb for lat={lat}, lng={lng}")
        return jsonify({'suburb': ''}), 200
    except requests.exceptions.ConnectionError as e:
        # Connection was reset or aborted
        logger.warning(f"Connection error resolving suburb (likely rate limited): {str(e)[:100]}")
        return jsonify({'error': 'Connection error'}), 503
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request error resolving suburb: {str(e)[:100]}")
        return jsonify({'suburb': ''}), 200
    except Exception as e:
        logger.error(f"Unexpected error resolving suburb: {e}")
        return jsonify({'suburb': ''}), 200


@app.route('/api/get_resolved_suburbs', methods=['POST'])
def api_get_resolved_suburbs():
    """
    API endpoint to get resolved suburbs for multiple crimes.
    Accepts: { "crimes": [{"crime_date": "YYYY-MM-DD", "crime_type": "...", "postcode": "..."}, ...] }
    Returns: { "resolved": {"crime_date|crime_type|postcode": "suburb_name", ...} }
    """
    try:
        data = request.get_json(silent=True) or {}
        crimes = data.get('crimes', [])

        if not crimes or not isinstance(crimes, list):
            return jsonify({'resolved': {}}), 200

        resolved = {}
        with get_resolved_suburbs_db_connection() as conn:
            for crime in crimes:
                crime_date = crime.get('crime_date', '')
                crime_type = crime.get('crime_type', '')
                postcode = crime.get('postcode', '')

                if not crime_date or not crime_type or not postcode:
                    continue

                row = conn.execute(
                    'SELECT suburb FROM resolved_suburbs WHERE crime_date = ? AND crime_type = ? AND postcode = ?',
                    (crime_date, crime_type, postcode)
                ).fetchone()

                if row:
                    key = f"{crime_date}|{crime_type}|{postcode}"
                    resolved[key] = row['suburb']

        logger.info(f"Loaded {len(resolved)} resolved suburbs from database")
        return jsonify({'resolved': resolved}), 200

    except Exception as e:
        logger.error(f"Error getting resolved suburbs: {e}")
        return jsonify({'resolved': {}}), 200


@app.route('/api/save_resolved_suburbs', methods=['POST'])
def api_save_resolved_suburbs():
    """
    API endpoint to batch save resolved suburbs.
    Accepts: { "suburbs": [{"crime_date": "...", "crime_type": "...", "postcode": "...", "suburb": "..."}, ...] }
    Returns: { "saved": number }
    """
    try:
        data = request.get_json(silent=True) or {}
        suburbs = data.get('suburbs', [])

        if not suburbs or not isinstance(suburbs, list):
            return jsonify({'saved': 0}), 200

        # Validate and filter the suburbs data
        valid_suburbs = []
        for suburb_data in suburbs:
            if not isinstance(suburb_data, dict):
                continue

            crime_date = suburb_data.get('crime_date', '')
            crime_type = suburb_data.get('crime_type', '')
            postcode = suburb_data.get('postcode', '')
            suburb = suburb_data.get('suburb', '')

            # Skip if any required field is missing
            if not crime_date or not crime_type or not postcode or not suburb:
                continue

            # Skip if suburb is still "Resolving..."
            if suburb.lower() == 'resolving...' or suburb.lower() == 'resolving':
                continue

            valid_suburbs.append({
                'crime_date': crime_date,
                'crime_type': crime_type,
                'postcode': postcode,
                'suburb': suburb
            })

        saved_count = batch_save_resolved_suburbs(valid_suburbs)
        return jsonify({'saved': saved_count}), 200

    except Exception as e:
        logger.error(f"Error saving resolved suburbs: {e}")
        return jsonify({'saved': 0}), 200


@app.route('/api/admin_stats')
def api_admin_stats():
    """Return overall stats across all reports. Admin-only."""
    if not session.get('admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with get_db_connection() as conn:
            total = conn.execute('SELECT COUNT(*) as c FROM reports').fetchone()['c']
            pending = conn.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'PENDING'").fetchone()['c']
            approved = conn.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'APPROVED'").fetchone()['c']
        return jsonify({ 'total_reports': total, 'pending': pending, 'approved': approved })
    except Exception as e:
        logger.error(f"Error computing admin stats: {e}")
        return jsonify({ 'total_reports': 0, 'pending': 0, 'approved': 0 }), 200


@app.route('/api/submit_crime', methods=['POST'])
def api_submit_crime():
    """JSON API to submit a crime report without page refresh."""
    data = request.get_json(silent=True) or {}
    lat = parse_coordinate(data.get('lat'))
    lng = parse_coordinate(data.get('lng'))
    address = (data.get('address') or '').strip()
    crime_type = (data.get('crime_type') or '').strip()
    crime_time = (data.get('crime_time') or '').strip()
    comment = (data.get('comment') or '').strip()
    anonymous = bool(data.get('anonymous'))
    admin_submit = str(data.get('admin_submit') or '').lower() == 'true'

    # Auth required: either user or admin session
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 401

    # Validate location
    if lat is None or lng is None or not validate_qld_coordinates(lat, lng):
        return jsonify({'error': 'Invalid or out-of-bounds location'}), 400

    # Validate fields
    if not crime_type or not crime_time:
        return jsonify({'error': 'Missing required fields'}), 400
    if not validate_crime_type(crime_type):
        return jsonify({'error': 'Invalid crime type selected'}), 400
    if crime_type == 'Other/Unsure':
        is_valid, error_msg = validate_comment(comment, config.COMMENT_WORD_LIMIT_OTHER_UNSURE)
        if not is_valid:
            return jsonify({'error': error_msg or 'Invalid comment'}), 400

    # Determine submitter and status
    submitter = f"ANON:{username}" if anonymous else username
    is_admin = bool(session.get('admin'))
    status = config.STATUS_APPROVED if (is_admin and admin_submit) else config.STATUS_PENDING

    rid = insert_report_with_id(
        crime_type=crime_type,
        crime_time=crime_time,
        lat=lat,
        lng=lng,
        address=address,
        submitted_by=submitter,
        status=status,
        comment=comment
    )
    if not rid:
        return jsonify({'error': 'Insert failed'}), 500

    return jsonify({
        'success': True,
        'id': rid,
        'status': status,
        'report': {
            'id': rid,
            'crime_type': crime_type,
            'crime_time': crime_time,
            'lat': lat,
            'lng': lng,
            'address': address,
            'submitted_by': submitter,
            'status': status,
            'comment': comment
        }
    }), 200

if __name__ == '__main__':
    # Initialize DB and run dev server
    init_db()
    init_resolved_suburbs_db()
    app.run(port=config.PORT, debug=config.DEBUG)