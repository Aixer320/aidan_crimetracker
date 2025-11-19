"""
Configuration and constants for Crime Tracker application.
"""
import os
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')
RESOLVED_SUBURBS_DB_PATH = os.path.join(BASE_DIR, 'resolved_suburbs.db')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
JSON_OUTPUT_PATH = os.path.join(STATIC_DIR, 'real_crimes_2025.json')

# Security
# CRITICAL: Set FLASK_SECRET_KEY environment variable in production
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-insecure-change-in-production')
# Warn if using default key
if SECRET_KEY == 'dev-insecure-change-in-production':
    print("WARNING: Using default SECRET_KEY. Set FLASK_SECRET_KEY environment variable in production!")

# Access control
ADMIN_ACCESS_CODE = os.environ.get('ADMIN_ACCESS_CODE', '1234')

# Coordinates bounds for Queensland
QLD_BOUNDS = {
    'lat_min': -29.5,
    'lat_max': -9.0,
    'lng_min': 137.995,
    'lng_max': 154.0,
}

# Status constants
STATUS_PENDING = 'PENDING'
STATUS_APPROVED = 'APPROVED'
STATUS_DISAPPROVED = 'DISAPPROVED'

VALID_STATUSES = {STATUS_PENDING, STATUS_APPROVED, STATUS_DISAPPROVED}

# Crime types whitelist
ALLOWED_CRIME_TYPES = {
    'Assault',
    'Robbery',
    'Other Offences Against the Person',
    'Unlawful Entry',
    'Other Property Damage',
    'Unlawful Use of Motor Vehicle',
    'Other Theft (excl. Unlawful Entry)',
    'Fraud',
    'Handling Stolen Goods',
    'Drug Offences',
    'Liquor',
    'Trespassing & Vagrancy',
    'Weapons Act Offences',
    'Good Order Offences',
    'Traffic & Related Offences',
    'Miscellaneous Offences',
    'Other/Unsure',
}

# Import settings
MAX_CSV_SIZE_MB = 50
MAX_COMMENT_LENGTH = 100
COMMENT_WORD_LIMIT_OTHER_UNSURE = 10
DEFAULT_DATE_RANGE_DAYS = 30

# Display overrides
TOTAL_OFFENCES_OVERRIDE = 157729  # Fixed total offences display value requested by user
# Set to None or 0 to disable override and use dynamic counts in frontend

# Database table names
TABLE_REPORTS = 'reports'
TABLE_ADMINS = 'admins'
TABLE_USERS = 'users'
TABLE_SETTINGS = 'settings'

# Settings keys
SETTING_LAST_UPDATED = 'last_updated'

# Server config
DEBUG = os.environ.get('FLASK_ENV') == 'development'
PORT = int(os.environ.get('PORT', 1009))
