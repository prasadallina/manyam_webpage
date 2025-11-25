from flask import Flask, request, session, render_template, redirect, url_for, jsonify
import os
import logging
import json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong secret key in production
app.config['UPLOAD_FOLDER'] = 'static/img'
app.config['GALLERY_FOLDER'] = 'static/gallery'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Ensure upload folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['GALLERY_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)

# Logging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# JSON file mappings for manyam District
FILES = {
    'home': 'data/manyam.json',
    'about': 'data/about.json',
    'contact': 'data/contact.json',
    'officers': 'data/officers.json',
    'organization': 'data/organization.json',
    'policestation': 'data/policestation.json',
    'services': 'data/services.json',
    'socialmedia': 'data/socialmedia.json',
    'wings': 'data/wings.json',
    'gallery': 'data/gallery.json'
}

# Admin credentials file
ADMIN_FILE = 'data/admin.json'

# Utility Functions
def load_data(file_path):
    try:
        if not os.path.exists(file_path):
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump({}, f, indent=2, ensure_ascii=False)
            return {}
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                logger.error(f"{file_path} does not contain a valid JSON object")
                return {}
            # Normalize image URLs in data
            def normalize_urls(obj):
                for key, value in obj.items():
                    if isinstance(value, dict):
                        normalize_urls(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                normalize_urls(item)
                    elif isinstance(value, str) and any(value.endswith(ext) for ext in ALLOWED_EXTENSIONS):
                        if value.startswith(('img/', 'gallery/')):
                            obj[key] = 'static/' + value
                        elif not value.startswith('static/'):
                            obj[key] = 'static/img/' + value.lstrip('/')
            normalize_urls(data)
            return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error loading {file_path}: {e}")
        return {}

def save_data(file_path, data):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Data saved to {file_path}")
    except Exception as e:
        logger.error(f"Error saving {file_path}: {e}")
        raise

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_admin():
    """Ensure admin credentials file exists. Default user: admin / admin123"""
    try:
        if not os.path.exists(ADMIN_FILE):
            default = {
                "username": "admin",
                "password": generate_password_hash('admin123')
            }
            save_data(ADMIN_FILE, default)
            logger.info('Created default admin credentials')
    except Exception as e:
        logger.error(f"Failed to initialize admin credentials: {e}")

# Initialize admin credentials on startup
init_admin()

# Public Routes
@app.route('/')
def index():
    data = load_data(FILES['home'])
    if not data or 'district' not in data:
        logger.error("Failed to load valid data from manyam.json, returning 404")
        return "Homepage data not found", 404
    return render_template('index.html', **data)

@app.route('/about')
def about():
    data = load_data(FILES['about'])
    return render_template('about.html', **data)

@app.route('/contact')
def contact():
    data = load_data(FILES['contact'])
    return render_template('contact.html', data=data)

@app.route('/officers')
def officers():
    data = load_data(FILES['officers'])
    return render_template('officers.html', **data)

@app.route('/organization')
def organization():
    data = load_data(FILES['organization'])
    return render_template('organization.html', **data)

@app.route('/policestation')
def policestation():
    data = load_data(FILES['policestation'])
    return render_template('policestation.html', data=data)

@app.route('/services')
def services():
    data = load_data(FILES['services'])
    return render_template('services.html', data=data)

@app.route('/socialmedia')
@app.route('/socialmedia.html')
def socialmedia():
    data = load_data(FILES['socialmedia'])
    if not data or 'district' not in data:
        logger.error("Failed to load valid data from socialmedia.json, returning 404")
        return "Social media data not found", 404
    return render_template('socialmedia.html', data=data)

@app.route('/wings')
def wings():
    data = load_data(FILES['wings'])
    return render_template('wings.html', data=data)

@app.route('/gallery')
def gallery():
    data = load_data(FILES['gallery'])  # Assuming FILES['gallery'] points to gallery.json
    return render_template('gallery.html', **data)



# Admin Routes
@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('admin.html', files=FILES.keys())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            admin_data = load_data(ADMIN_FILE)
            stored_user = admin_data.get('username', 'admin')
            stored_pw = admin_data.get('password')
            if username == stored_user and stored_pw and check_password_hash(stored_pw, password):
                session['logged_in'] = True
                return redirect(url_for('admin'))
        except Exception as e:
            logger.error(f"Login error: {e}")
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/admin/data/<section>')
def get_section_data(section):
    if not session.get('logged_in'):
        return "Unauthorized", 401
    if section in FILES:
        return jsonify(load_data(FILES[section]))
    return "Not found", 404

@app.route('/admin/save/<section>', methods=['POST'])
def save_section(section):
    if not session.get('logged_in'):
        return "Unauthorized", 401
    if section in FILES:
        try:
            new_data = request.get_json()
            if not isinstance(new_data, dict):
                return "Invalid data format", 400
            current_data = load_data(FILES[section])
            current_data.update(new_data)  # Merge new data with existing data
            save_data(FILES[section], current_data)
            return "Saved", 200
        except Exception as e:
            logger.error(f"Error saving {section}: {e}")
            return f"Error: {str(e)}", 500
    return "Not found", 404

# Image Upload
@app.route('/admin/upload_image', methods=['POST'])
def upload_image():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    file = request.files['image']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file"}), 400

    filename = secure_filename(file.filename)
    # Determine target folder based on referrer or default to UPLOAD_FOLDER
    target_folder = app.config['GALLERY_FOLDER'] if 'carousel' in request.referrer or 'gallery' in request.referrer else app.config['UPLOAD_FOLDER']
    save_path = os.path.join(target_folder, filename)

    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(save_path):
        filename = f"{base}_{counter}{ext}"
        save_path = os.path.join(target_folder, filename)
        counter += 1

    try:
        file.save(save_path)
        logger.info(f"Image saved to {save_path}")
        relative_path = os.path.join('static', os.path.basename(target_folder), filename).replace('\\', '/')
        return jsonify({"url": relative_path}), 200
    except Exception as e:
        logger.error(f"Error saving image {filename}: {e}")
        return jsonify({"error": f"Error saving image: {e}"}), 500

# Reset Password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Change admin password. Requires current_password, new_password and confirm_password in form."""
    current = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if not current or not new_password or not confirm_password:
        return render_template('login.html', error='All password fields are required')
    if new_password != confirm_password:
        return render_template('login.html', error='New password and confirm password do not match')
    try:
        admin_data = load_data(ADMIN_FILE)
        stored_pw = admin_data.get('password')
        if not stored_pw or not check_password_hash(stored_pw, current):
            return render_template('login.html', error='Current password is incorrect')
        # Update password
        admin_data['password'] = generate_password_hash(new_password)
        save_data(ADMIN_FILE, admin_data)
        return render_template('login.html', success='Password changed successfully')
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return render_template('login.html', error='Failed to change password')

# After Request
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

# Run App
if __name__ == '__main__':
    app.run(debug=True)