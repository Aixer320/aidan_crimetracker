CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    year_level INTEGER NOT NULL,
    gender TEXT NOT NULL,
    house TEXT NOT NULL
);

CREATE TABLE nominations (
    nomination_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    event TEXT NOT NULL,
    gender TEXT NOT NULL,
    house TEXT NOT NULL,
    year_level TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    occupation TEXT NOT NULL,
    admin_type TEXT NOT NULL,
    house TEXT
);