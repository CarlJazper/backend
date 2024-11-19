import csv
import os
from db import get_db_connection
import hashlib
import sqlite3

def save_log_to_db(log_data, filename, upload_date, user_email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (log_data, filename, upload_date, user_email)
        VALUES (?, ?, ?, ?)
    ''', (log_data, filename, upload_date, user_email))
    conn.commit()
    conn.close()

def save_analysis_to_db(analysis_results, filename, upload_date, user_email):
    conn = get_db_connection()
    cursor = conn.cursor()
    for event in analysis_results:
        cursor.execute('''
            INSERT INTO analysis_results (timestamp, source, message, suspicious, reason, severity, filename, upload_date, user_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get('timestamp'), event.get('source'), event.get('message'),
            event.get('suspicious'), event.get('reason', ''), event.get('severity'),
            filename, upload_date, user_email
        ))
    conn.commit()
    conn.close()


def save_analysis_to_csv(analysis_results, filename):
    csv_path = os.path.join("exports", filename)
    os.makedirs("exports", exist_ok=True)
    headers = ['timestamp', 'source', 'message', 'suspicious', 'reason', 'severity']
    with open(csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(analysis_results)
    return filename


from werkzeug.security import generate_password_hash, check_password_hash

def save_user_to_db(fname, lname, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Hash the password using werkzeug
    hashed_password = generate_password_hash(password)

    try:
        cursor.execute('''
            INSERT INTO users (fname, lname, email, password)
            VALUES (?, ?, ?, ?)
        ''', (fname, lname, email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("User with that email already exists")
    finally:
        conn.close()


def authenticate_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM users WHERE email = ?
    ''', (email,))
    
    user = cursor.fetchone()
    conn.close()

    # If user exists, check the hashed password
    if user and check_password_hash(user['password'], password):
        return True
    return False
