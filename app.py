from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from log_analysis import analyze_logs
from utils import save_log_to_db, save_analysis_to_db, save_analysis_to_csv
import os
from db import get_db_connection
from dotenv import load_dotenv
from datetime import datetime, timedelta
from utils import save_user_to_db, authenticate_user
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
    
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_email = decoded['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Route to get user profile
@app.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    try:
        user_email = request.user_email  # Get the email from the decoded token
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT fname, lname, email FROM users WHERE email = ?', (user_email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify(dict(user)), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/change_password', methods=['PUT'])
@require_auth
def change_password():
    try:
        data = request.get_json()
        current_password = data['current_password']
        new_password = data['new_password']
        user_email = request.user_email

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch the current hashed password from the database
        cursor.execute('SELECT password FROM users WHERE email = ?', (user_email,))
        user = cursor.fetchone()

        # Check if the current password matches the stored hashed password
        if not user or not check_password_hash(user['password'], current_password):
            return jsonify({'message': 'Current password is incorrect'}), 401

        # Hash the new password and update it
        hashed_new_password = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_new_password, user_email))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

def clean_analysis_results(analysis_results):
    # Define the valid fieldnames explicitly
    valid_fieldnames = ['timestamp', 'source', 'message', 'suspicious', 'severity', 'reason']

    for result in analysis_results:
        for key in list(result.keys()):
            if key not in valid_fieldnames:
                del result[key] 
    
    return analysis_results

@app.route('/upload_log', methods=['POST'])
@require_auth
def upload_log():
    if 'logfile' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    try:
        log_data = file.read().decode('utf-8')
        filename = file.filename
        upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Save log data with user association
        user_email = request.user_email
        save_log_to_db(log_data, filename, upload_date, user_email)
        # Analyze logs
        analysis_results = analyze_logs(log_data)
        cleaned_results = clean_analysis_results(analysis_results)
        # Save analysis with user association
        save_analysis_to_db(cleaned_results, filename, upload_date, user_email)
        # Save analysis results to CSV
        csv_filename = f"{filename.split('.')[0]}_analysis.csv"
        csv_file_path = save_analysis_to_csv(cleaned_results, csv_filename)
        
        return jsonify({
            'message': 'Log uploaded successfully!',
            'analysis': cleaned_results,
            'csv_file_path': f'http://localhost:5000/download_csv/{csv_filename}'
        })
    except Exception as e:
        return jsonify({'message': f'Error processing file: {str(e)}'}), 500


# Route to download analysis CSV file
@app.route('/download_csv/<filename>', methods=['GET'])
def download_csv(filename):
    csv_path = os.path.join("exports", filename)
    try:
        return send_file(csv_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'message': 'File not found'}), 404

# Route to get all logs with pagination
@app.route('/logs', methods=['GET'])
@require_auth
def get_logs():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 5))
        offset = (page - 1) * limit
        user_email = request.user_email

        conn = get_db_connection()
        logs = conn.execute(
            'SELECT * FROM logs WHERE user_email = ? ORDER BY upload_date DESC LIMIT ? OFFSET ?',
            (user_email, limit, offset)
        ).fetchall()
        total_logs = conn.execute('SELECT COUNT(*) FROM logs WHERE user_email = ?', (user_email,)).fetchone()[0]
        conn.close()

        logs = [dict(log) for log in logs]  # Convert rows to dict

        return jsonify({
            'logs': logs,
            'total': total_logs,
            'page': page,
            'limit': limit,
            'pages': (total_logs + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({'message': f'Error fetching logs: {str(e)}'}), 500


# Route to get all analysis results for the authenticated user
@app.route('/analysis_results', methods=['GET'])
@require_auth
def get_analysis_results():
    try:
        user_email = request.user_email  # Get the email from the decoded token
        conn = get_db_connection()
        # Fetch analysis results only for the authenticated user
        results = conn.execute(
            'SELECT * FROM analysis_results WHERE user_email = ? ORDER BY upload_date DESC', 
            (user_email,)
        ).fetchall()
        conn.close()
        return jsonify([dict(result) for result in results])
    except Exception as e:
        return jsonify({'message': f'Error fetching analysis results: {str(e)}'}), 500

# Route to get suspicious analysis results for the authenticated user
@app.route('/suspicious_analysis_results', methods=['GET'])
@require_auth
def get_suspicious_analysis_results():
    try:
        user_email = request.user_email  # Get the email from the decoded token
        conn = get_db_connection()
        # Fetch suspicious analysis results only for the authenticated user
        suspicious_results = conn.execute(
            '''
            SELECT * FROM analysis_results 
            WHERE user_email = ? AND (severity IN ('High', 'Medium') OR reason IS NOT NULL) 
            ORDER BY upload_date DESC
            ''', 
            (user_email,)
        ).fetchall()
        conn.close()
        return jsonify([dict(result) for result in suspicious_results])
    except Exception as e:
        return jsonify({'message': f'Error fetching suspicious analysis results: {str(e)}'}), 500


@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        fname = data['fname']
        lname = data['lname']
        email = data['email']
        password = data['password']
        
        # Save user to database (you can extend this with additional fields as needed)
        save_user_to_db(fname, lname, email, password)
        return jsonify({'message': 'User successfully registered!'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400

# Add a secret key for JWT
SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        
        if authenticate_user(email, password):
            # Generate a JWT token
            token = jwt.encode({
                'email': email,
                'exp': datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
            }, SECRET_KEY, algorithm='HS256')

            return jsonify({'message': 'Login successful', 'token': token}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
