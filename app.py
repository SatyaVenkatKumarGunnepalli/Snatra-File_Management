from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, abort, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import mimetypes
import logging
import csv
import secrets
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Use a secure, random secret key

# Define file paths
BASE_DIR = 'files'
LOG_FILE = 'logs/app.log'
REPORT_FILE = 'missing_documents_report.csv'
BASE_DIR_REPORT = 'files/SnatraPharmaceuticals'
EXPECTED_DOCS = ['PO', 'COA', 'INVOICE', 'EWayBill', 'LR']

app.config['UPLOAD_FOLDER'] = BASE_DIR

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Example user database with hashed passwords
users = {
    'user': {'password': generate_password_hash('password'), 'active': False},
    'bhavani@123': {'password': generate_password_hash('password123'), 'active': False},
    'pravin@987': {'password': generate_password_hash('password987'), 'active': False}
}

# Example Admin database with hashed passwords
admins = {
    'admin': {'password': generate_password_hash('adminpass'), 'active': False},
    'admin1': {'password': generate_password_hash('adminpass'), 'active': False}
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in users or user_id in admins:
        return User(user_id)
    return None


class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.username = getattr(record, 'username', 'System')
        return super().format(record)

def setup_logging():
    if not os.path.exists(os.path.dirname(LOG_FILE)):
        os.makedirs(os.path.dirname(LOG_FILE))

    handler = logging.FileHandler(LOG_FILE)
    formatter = CustomFormatter('%(asctime)s - %(levelname)s - [%(username)s] - %(message)s')
    handler.setFormatter(formatter)

    logging.basicConfig(
        handlers=[handler],
        level=logging.INFO
    )

setup_logging()

def log_user_action(action):
    username = current_user.id if current_user.is_authenticated else 'Anonymous'
    logging.info(action, extra={'username': username})

def check_documents(folder_path):
    existing_folders = [doc for doc in EXPECTED_DOCS if os.path.isdir(os.path.join(folder_path, doc))]
    missing_docs = {doc: True for doc in existing_folders}  # Initialize all as missing

    try:
        for doc in existing_folders:
            doc_folder_path = os.path.join(folder_path, doc)
            if os.listdir(doc_folder_path):  # Folder is not empty
                missing_docs[doc] = False
    except Exception as e:
        log_user_action(f"Error accessing folder {folder_path}: {e}")
    
    return [doc for doc, missing in missing_docs.items() if missing]

def scan_folder_for_missing_docs(company_folder):
    report = []
    for category in ['Transactions', 'Purchase', 'Sales']:
        category_path = os.path.join(company_folder, category)
        if not os.path.exists(category_path):
            continue
        for month_folder in os.listdir(category_path):
            month_path = os.path.join(category_path, month_folder)
            if not os.path.isdir(month_path):
                continue
            for day_folder in os.listdir(month_path):
                day_path = os.path.join(month_path, day_folder)
                if os.path.isdir(day_path):
                    missing_docs = check_documents(day_path)
                    if missing_docs:
                        report.append({
                            'CompanyFolder': os.path.basename(company_folder),
                            'Category': category,
                            'Month': month_folder,
                            'DayFolder': day_folder,
                            'MissingDocuments': missing_docs
                        })
    return report

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            login_user(User(username))
            users[username]['active'] = True
            redirect_url = request.args.get('next') or url_for('index')
            log_user_action(f"User {username} logged in successfully, redirecting to {redirect_url}")
            return redirect(redirect_url)
        
        admin = admins.get(username)
        if admin and check_password_hash(admin['password'], password):
            login_user(User(username))
            admins[username]['active'] = True
            redirect_url = request.args.get('next') or url_for('admin_page')
            log_user_action(f"Admin {username} logged in successfully, redirecting to {redirect_url}")
            return redirect(redirect_url)
        
        log_user_action(f"Invalid login attempt for username: {username}")
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    if current_user.id in users:
        users[current_user.id]['active'] = False
    elif current_user.id in admins:
        admins[current_user.id]['active'] = False
    
    log_user_action(f"User {current_user.id} logged out")
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/admin')
@login_required
def admin_page():
    if current_user.id not in admins:
        return redirect(url_for('login', next=url_for('admin_page')))
    return render_template('admin.html')

@app.route('/list', methods=['GET'])
@login_required
def list_files():
    path = request.args.get('path', '')
    full_path = os.path.join(BASE_DIR, path)

    if not os.path.exists(full_path):
        return jsonify({'error': 'Directory not found'}), 404

    files = []
    try:
        for entry in os.scandir(full_path):
            files.append({
                'name': entry.name,
                'type': 'folder' if entry.is_dir() else 'file',
                'path': os.path.relpath(entry.path, BASE_DIR)
            })
    except Exception as e:
        log_user_action(f"Exception: {str(e)}")
        return jsonify({'error': f'Internal Server Error: {str(e)}'}), 500

    return jsonify(files)

@app.route('/metadata/<path:filename>', methods=['GET'])
@login_required
def file_metadata(filename):
    path = os.path.normpath(os.path.join(BASE_DIR, filename))
    if os.path.exists(path):
        stats = os.stat(path)
        metadata = {
            'size': stats.st_size,
            'modified': stats.st_mtime
        }
        return jsonify(metadata)
    return jsonify({'error': 'File not found'}), 404

@app.route('/download/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    path = os.path.normpath(os.path.join(BASE_DIR, filename))
    if os.path.exists(path):
        log_user_action(f"User {current_user.id} downloaded file: {filename}")
        return send_file(path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/rename', methods=['POST'])
@login_required
def rename_file_or_folder():
    data = request.json
    old_name = data.get('old_name')
    new_name = data.get('new_name')

    if not old_name or not new_name:
        return jsonify({'error': 'Both old and new names must be provided'}), 400

    old_path = os.path.normpath(os.path.join(BASE_DIR, old_name))
    new_path = os.path.normpath(os.path.join(BASE_DIR, new_name))

    if not old_path.startswith(BASE_DIR) or not new_path.startswith(BASE_DIR):
        return jsonify({'error': 'Invalid path'}), 400

    if not os.path.exists(old_path):
        return jsonify({'error': 'Old path not found'}), 404

    if os.path.exists(new_path):
        return jsonify({'error': 'New path already exists'}), 400

    try:
        log_user_action(f"User {current_user.id} attempting to rename from {old_path} to {new_path}")
        os.rename(old_path, new_path)
        return '', 204
    except OSError as e:
        log_user_action(f"OSError: {str(e)}")
        return jsonify({'error': f'OSError: {str(e)}'}), 500
    except Exception as e:
        log_user_action(f"Unexpected error: {str(e)}")
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    data = request.json
    folder_name = data.get('name')

    if not folder_name:
        return jsonify({'error': 'No folder name provided'}), 400

    path = os.path.normpath(os.path.join(BASE_DIR, folder_name))

    if not os.path.commonpath([BASE_DIR, path]) == BASE_DIR:
        return jsonify({'error': 'Invalid folder path'}), 400

    try:
        os.makedirs(path, exist_ok=True)
        log_user_action(f"User {current_user.id} created folder: {folder_name}")
        return '', 204
    except Exception as e:
        log_user_action(f"Error creating folder: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    log_user_action('Upload request received')
    
    if 'file' not in request.files:
        log_user_action('No file part in request')
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    
    if file.filename == '':
        log_user_action('No selected file')
        return jsonify({'error': 'No selected file'}), 400

    folder_path = request.form.get('folder_path', '')
    safe_folder_path = os.path.normpath(folder_path).lstrip(os.sep)
    full_path = os.path.join(BASE_DIR, safe_folder_path)
    
    log_user_action(f'Saving file to: {full_path}')

    if not os.path.commonpath([BASE_DIR, full_path]) == BASE_DIR:
        log_user_action('Invalid folder path')
        return jsonify({'error': 'Invalid folder path'}), 400

    if not os.path.isdir(full_path):
        log_user_action('Directory does not exist')
        return jsonify({'error': 'Directory does not exist'}), 404

    file_path = os.path.join(full_path, secure_filename(file.filename))
    
    log_user_action(f'Saving file to: {file_path}')

    try:
        file.save(file_path)
        log_user_action(f"User {current_user.id} uploaded file: {file.filename} to {safe_folder_path}")
        return jsonify({'message': 'File uploaded successfully'}), 200
    except Exception as e:
        log_user_action(f"Error saving file: {str(e)}")
        return jsonify({'error': f'Error saving file: {str(e)}'}), 500

@app.route('/view/<path:filename>', methods=['GET'])
@login_required
def view_file(filename):
    path = os.path.normpath(os.path.join(BASE_DIR, filename))
    if os.path.exists(path):
        mime_type, _ = mimetypes.guess_type(path)
        if mime_type is None:
            mime_type = 'application/octet-stream'
        try:
            log_user_action(f"User {current_user.id} viewed file: {filename}")
            return send_file(path, mimetype=mime_type)
        except Exception as e:
            log_user_action(f"Error sending file: {str(e)}")
            return jsonify({'error': f'Error sending file: {str(e)}'}), 500
    return jsonify({'error': 'File not found'}), 404

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    try:
        all_reports = []
        for company_folder in os.listdir(BASE_DIR_REPORT):
            company_path = os.path.join(BASE_DIR_REPORT, company_folder)
            if os.path.isdir(company_path):
                log_user_action(f"Processing {company_folder}...")
                company_report = scan_folder_for_missing_docs(company_path)
                all_reports.extend(company_report)

        with open(REPORT_FILE, 'w', newline='') as csvfile:
            fieldnames = ['CompanyFolder', 'Category', 'Month', 'DayFolder', 'MissingDocuments']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in all_reports:
                writer.writerow({
                    'CompanyFolder': entry['CompanyFolder'],
                    'Category': entry['Category'],
                    'Month': entry['Month'],
                    'DayFolder': entry['DayFolder'],
                    'MissingDocuments': ', '.join(entry['MissingDocuments'])
                })
        log_user_action('Report generated successfully')
        return jsonify({'message': 'Report generated successfully'}), 200
    except Exception as e:
        log_user_action(f"Error generating report: {e}")
        return jsonify({'error': f'Error generating report: {e}'}), 500

@app.route('/download_report', methods=['GET'])
@login_required
def download_report():
    if os.path.exists(REPORT_FILE):
        log_user_action(f"User {current_user.id} downloaded the report")
        return send_file(REPORT_FILE, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404

@app.route('/current_user', methods=['GET'])
@login_required
def current_user_status():
    return jsonify({'username': current_user.id}), 200

@app.route('/api/users', methods=['GET'])
@login_required
def api_user_list():
    if current_user.id not in admins:
        return jsonify({'error': 'Unauthorized'}), 403

    user_data = [{'username': username, 'status': 'Active' if details.get('active', False) else 'Inactive'}
                  for username, details in users.items()]
    
    return jsonify(user_data)

@app.route('/admin/users', methods=['GET'])
@login_required
def admin_user_list():
    if current_user.id not in admins:
        return redirect(url_for('login', next=url_for('admin_user_list')))
    
    user_data = [{'username': username, 'status': 'Active' if details.get('active', False) else 'Inactive'}
                  for username, details in users.items()]
    
    return render_template('admin.html', users=user_data)

@app.route('/user-logs', methods=['GET'])
@login_required
def user_logs():
    if current_user.id not in admins:
        return jsonify({'error': 'Unauthorized access.'}), 403

    logs = []
    try:
        with open(LOG_FILE, 'r') as logfile:
            log_lines = logfile.readlines()
            for line in log_lines:
                clean_line = re.sub(r'\x1b\[.*?m', '', line).strip()
                # Updated regex to match your log format
                match = re.match(r'^(.*?) - (.*?) - \[(.*?)\] - (.*)$', clean_line)
                if match:
                    timestamp, level, user_id, action_details = match.groups()
                    # Split action and details if they exist
                    action, details = action_details.split(' - ', 1) if ' - ' in action_details else (action_details, '')
                    logs.append({
                        'timestamp': timestamp,
                        'username': user_id,
                        'action': action,
                        'details': details.strip()  # Strip any extra whitespace from details
                    })

    except Exception as e:
        log_user_action(f"Error reading log file: {str(e)}")
        return jsonify({'error': 'Error reading log file.'}), 500

    return jsonify({'logs': logs})

def admin_required(f):
    """Decorator to restrict access to admin users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id not in admins:
            return redirect(url_for('login', next=url_for('admin_page')))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/view_report', methods=['GET'])
@login_required
def view_report():
    if not os.path.exists(REPORT_FILE):
        return jsonify({'error': 'Report not found'}), 404

    try:
        with open(REPORT_FILE, 'r') as file:
            report_content = file.read()
        
        log_user_action("Report viewed")
        return Response(report_content, mimetype='text/csv')
    
    except Exception as e:
        log_user_action(f"Error reading report file: {str(e)}")
        return jsonify({'error': f'Error reading report file: {str(e)}'}), 500

@app.before_request
def before_request():
    log_user_action(f"Request Path: {request.path}")
    log_user_action(f"User Logged In: {current_user.is_authenticated}")

@app.after_request
def after_request(response):
    log_user_action(f"Response Status: {response.status}")
    return response

if __name__ == '__main__':
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
    if not os.path.exists(BASE_DIR_REPORT):
        os.makedirs(BASE_DIR_REPORT)

    app.run(debug=True)
