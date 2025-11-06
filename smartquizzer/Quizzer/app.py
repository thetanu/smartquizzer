from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # [MODULE 2] Added for file uploads
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import json
from groq import Groq
import re
from typing import List, Dict, Any, Optional
import difflib
import functools # [MODULE 6] For admin required decorator

# [MODULE 2] Import PDF/Text processing libraries
# You will need to install these: pip install PyMuPDF requests beautifulsoup4
try:
    import fitz  # PyMuPDF
except ImportError:
    print("PyMuPDF (fitz) not installed. PDF processing will not work.")
    print("Please run: pip install PyMuPDF")
    fitz = None

try:
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, urljoin
except ImportError:
    print("Web scraping libraries not installed. URL processing will not work.")
    print("Please run: pip install requests beautifulsoup4")
    requests = None
    BeautifulSoup = None

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# [MODULE 2] Config for file uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


db = SQLAlchemy(app)

def get_groq_client():
    api_key = os.getenv('GROQ_API_KEY')
    # This check ensures the key is not None AND is not the placeholder
    if not api_key or api_key == 'your_groq_api_key here' or 'your-key-here' in api_key.lower():
         raise ValueError("GROQ_API_KEY not set correctly. Please create/check the .env file with your real Groq API key.")
    return Groq(api_key=api_key)

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False) # [MODULE 6] Admin flag

    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True)
    profile = db.relationship('Profile', backref='user', uselist=False, lazy=True) # [MODULE 1]
    materials = db.relationship('LearningMaterial', backref='user', lazy=True) # [MODULE 2]
    feedback = db.relationship('QuestionFeedback', backref='user', lazy=True) # [MODULE 6]


class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # [MODULE 1] Link to profile history
    answers = db.relationship('QuizAnswer', backref='attempt', lazy=True, cascade="all, delete-orphan")


class QuizAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(32), nullable=False)
    options_json = db.Column(db.Text, nullable=True)  # JSON-serialized list for MCQs
    correct_answer_json = db.Column(db.Text, nullable=True)
    user_answer_json = db.Column(db.Text, nullable=True)
    is_correct = db.Column(db.Boolean, default=False)
    explanation = db.Column(db.Text, nullable=True)
    time_spent_seconds = db.Column(db.Integer, default=0)

# [MODULE 1] New Profile Model
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    subjects_of_interest = db.Column(db.Text, nullable=True) # Stored as comma-separated string
    preferred_difficulty = db.Column(db.String(20), default='medium')

    # performance_history is derived from QuizAttempt and QuizAnswer models

# [MODULE 2] New LearningMaterial Model
class LearningMaterial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False) # The extracted text content
    material_type = db.Column(db.String(20), nullable=False) # 'pdf', 'url', 'text'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# [MODULE 6] New QuestionFeedback Model
class QuestionFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Nullable if anonymous
    question_text = db.Column(db.Text, nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    is_flagged = db.Column(db.Boolean, default=False) # e.g., "inappropriate/wrong"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)


# Create tables
with app.app_context():
    db.create_all()

# --- Decorators ---

def login_required(f):
    """A decorator to ensure the user is logged in."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f): # [MODULE 6]
    """A decorator to ensure the user is an admin."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
@login_required
def index():
    # User is already confirmed to be in session by @login_required
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
         return redirect(url_for('index'))
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if user and check_password_hash(user.password, data['password']):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin # [MODULE 6] Set admin flag in session
            return jsonify({'success': True, 'message': 'Login successful'})

        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
         return redirect(url_for('index'))
    if request.method == 'POST':
        data = request.get_json()

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        hashed_password = generate_password_hash(data['password'])
        # [MODULE 6] Make the first registered user an admin for demo purposes
        is_first_user = User.query.count() == 0

        new_user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            is_admin=is_first_user # [MODULE 6]
        )

        db.session.add(new_user)
        db.session.commit() # Commit user first to get ID

        # [MODULE 1] Create a default profile for the new user
        new_profile = Profile(user_id=new_user.id, preferred_difficulty='medium')
        db.session.add(new_profile)
        db.session.commit() # Commit profile

        if is_first_user:
             flash('Registration successful. You are the first user, so you have been granted admin privileges.', 'success')

        return jsonify({'success': True, 'message': 'Registration successful'})

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            # Note: Don't reveal if an email exists or not for security
            return jsonify({'success': True, 'message': 'If an account exists with that email, a reset link simulation is triggered.'})

        # In a real app, send email with token.
        # For this demo, we'll just pass the user_id (INSECURE)
        flash('Password reset email sent (simulation). Please check your inbox.', 'info')
        # This user_id passing is insecure, only for demonstration.
        return jsonify({'success': True, 'message': 'Simulating reset link generation. Redirecting...', 'user_id': user.id})

    return render_template('forgot-password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    # In a real app, this route would be /reset-password/<token>
    if request.method == 'POST':
        data = request.get_json()
        user_id = data.get('user_id') # This is insecure, only for demo
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password') # Added confirmation check

        if not user_id or not new_password or not confirm_password:
             return jsonify({'success': False, 'message': 'All fields are required'}), 400

        if new_password != confirm_password:
             return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'Invalid user or expired link'}), 404

        user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password has been changed successfully. Please log in.', 'success')
        return jsonify({'success': True, 'message': 'Password has been changed successfully'})

    # This GET part relies on the insecure user_id from forgot_password simulation
    user_id = request.args.get('user_id')
    if not user_id:
        flash('Invalid or missing reset identifier.', 'danger')
        return redirect(url_for('login'))
    return render_template('reset-password.html', user_id=user_id)


# --- [MODULE 1] Profile Management ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    profile = Profile.query.filter_by(user_id=session['user_id']).first()
    if not profile:
        # Create one if it doesn't exist (shouldn't happen with register logic)
        profile = Profile(user_id=session['user_id'])
        db.session.add(profile)
        db.session.commit()

    if request.method == 'POST':
        profile.subjects_of_interest = request.form.get('subjects_of_interest', '').strip()
        profile.preferred_difficulty = request.form.get('preferred_difficulty', 'medium')
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # [MODULE 1] Get performance history
    attempts = QuizAttempt.query.filter_by(user_id=session['user_id']).order_by(QuizAttempt.completed_at.desc()).limit(10).all()
    history = [{
        'id': a.id,
        'topic': a.topic,
        'score': a.score,
        'total': a.total_questions,
        'percentage': round((a.score / a.total_questions) * 100, 1) if a.total_questions > 0 else 0,
        'date': a.completed_at.strftime('%Y-%m-%d %H:%M') # More precise date
    } for a in attempts]

    return render_template('profile.html', profile=profile, history=history, username=session.get('username'))


# --- [MODULE 2] Content Ingestion ---

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def process_pdf(filepath: str) -> str:
    """Extracts text from a PDF file."""
    if not fitz:
        return "Error: PyMuPDF (fitz) is not installed. Cannot process PDF."

    text = ""
    try:
        with fitz.open(filepath) as doc:
            for page in doc:
                text += page.get_text() + "\n" # Add newline between pages
    except Exception as e:
        print(f"Error processing PDF {filepath}: {str(e)}")
        return f"Error processing PDF: {str(e)}"

    # Basic cleaning (replace multiple whitespace/newlines with single space)
    cleaned_text = re.sub(r'\s+', ' ', text).strip()
    # TODO: Add more advanced NLP chunking here if needed
    return cleaned_text

def process_url(url: str) -> str:
    """Fetch and parse text content from a URL."""
    if not requests or not BeautifulSoup:
        return "Error: Web scraping libraries (requests, beautifulsoup4) are not installed. Please install them with: pip install requests beautifulsoup4"
    
    try:
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return "Error: Invalid URL format. Please provide a complete URL (e.g., https://example.com)"
        
        # Add protocol if missing
        if not parsed_url.scheme:
            url = 'https://' + url
            parsed_url = urlparse(url)
        
        print(f"[INFO] Processing URL: {url}")
        
        # Set headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Make request with timeout
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()  # Raise exception for bad status codes
        
        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' not in content_type:
            return f"Error: URL does not contain HTML content. Content type: {content_type}"
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "header", "footer", "aside"]):
            script.decompose()
        
        # Extract text from main content areas
        text_content = ""
        
        # Try to find main content areas
        main_content = soup.find('main') or soup.find('article') or soup.find('div', class_=re.compile(r'content|main|article|post'))
        
        if main_content:
            text_content = main_content.get_text()
        else:
            # Fallback to body content
            body = soup.find('body')
            if body:
                text_content = body.get_text()
            else:
                text_content = soup.get_text()
        
        # Clean up the text
        cleaned_text = re.sub(r'\s+', ' ', text_content).strip()
        
        # Check if we got meaningful content
        if len(cleaned_text) < 100:
            return f"Error: Could not extract sufficient content from URL. Only found {len(cleaned_text)} characters. The page might be empty or require JavaScript to load content."
        
        # Limit content length to prevent memory issues
        if len(cleaned_text) > 50000:
            cleaned_text = cleaned_text[:50000] + "... [Content truncated]"
        
        print(f"[INFO] Successfully extracted {len(cleaned_text)} characters from {url}")
        return cleaned_text
        
    except requests.exceptions.Timeout:
        return "Error: Request timed out. The website took too long to respond."
    except requests.exceptions.ConnectionError:
        return "Error: Could not connect to the URL. Please check if the URL is correct and accessible."
    except requests.exceptions.HTTPError as e:
        return f"Error: HTTP error {e.response.status_code}. The website returned an error."
    except requests.exceptions.RequestException as e:
        return f"Error: Request failed - {str(e)}"
    except Exception as e:
        print(f"[ERROR] Unexpected error processing URL {url}: {e}")
        return f"Error: Unexpected error occurred while processing the URL - {str(e)}"

def process_text(text: str) -> str:
    """Basic cleaning for pasted text."""
    cleaned_text = re.sub(r'\s+', ' ', text).strip()
    # TODO: Add more advanced NLP chunking here if needed
    return cleaned_text


@app.route('/upload-material', methods=['GET', 'POST'])
@login_required
def upload_material():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        # Use the hidden input value which JS updates
        upload_type = request.form.get('upload_type') 

        if not title:
            flash('Please provide a title for your material.', 'danger')
            return redirect(request.url)

        content = ""
        material_type = "text" # Default

        if upload_type == 'text':
            pasted_content = request.form.get('pasted_text', '')
            if not pasted_content.strip():
                 flash('Pasted text cannot be empty.', 'danger')
                 return redirect(request.url)
            content = process_text(pasted_content)
            material_type = "text"

        elif upload_type == 'url':
            material_url = request.form.get('material_url', '')
            if not material_url.strip():
                 flash('URL cannot be empty.', 'danger')
                 return redirect(request.url)
            
            content = process_url(material_url)
            material_type = "url"
            
            # Check if URL processing failed
            if content.startswith("Error:"):
                flash(f'URL processing failed: {content}', 'danger')
                return redirect(request.url)


        elif upload_type == 'file':
            if 'material_file' not in request.files:
                flash('No file part selected.', 'danger')
                return redirect(request.url)
            file = request.files['material_file']
            if file.filename == '':
                flash('No file selected for upload.', 'danger')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}")
                try:
                    file.save(filepath)

                    if filename.lower().endswith('.pdf'):
                        content = process_pdf(filepath)
                        material_type = "pdf"
                    elif filename.lower().endswith('.txt'):
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                content = process_text(f.read())
                            material_type = "text"
                        except Exception as read_err:
                            flash(f'Error reading text file: {read_err}', 'danger')
                            os.remove(filepath) # Clean up failed upload
                            return redirect(request.url)

                    # Optional: Remove the file after processing if no longer needed
                    # os.remove(filepath)

                    # Check if PDF processing itself returned an error message
                    if content.startswith("Error:"):
                        flash(content, 'danger')
                        if os.path.exists(filepath): os.remove(filepath)
                        return redirect(request.url)

                except Exception as save_err:
                     flash(f'Error saving or processing file: {save_err}', 'danger')
                     if os.path.exists(filepath): os.remove(filepath) # Clean up partial upload
                     return redirect(request.url)

            else:
                flash('Invalid file type. Only PDF and TXT files are allowed.', 'danger')
                return redirect(request.url)
        else:
             flash('Invalid upload type selected.', 'danger')
             return redirect(request.url)


        # Final check if content extraction succeeded before saving
        if not content or not content.strip() or content.startswith("Error:"):
            flash('Could not extract meaningful content from the source. Please check the source or try a different method.', 'danger')
            # Clean up uploaded file if it exists and failed
            if upload_type == 'file' and 'filepath' in locals() and os.path.exists(filepath):
                 os.remove(filepath)
            return redirect(request.url)

        # Save to database
        new_material = LearningMaterial(
            user_id=session['user_id'],
            title=title,
            content=content,
            material_type=material_type
        )
        db.session.add(new_material)
        db.session.commit()

        flash(f'Material "{title}" ({material_type.upper()}) processed and saved successfully!', 'success')
        return redirect(url_for('list_materials'))

    return render_template('upload_material.html')

@app.route('/materials')
@login_required
def list_materials():
    """Lists all uploaded materials for the user."""
    materials = LearningMaterial.query.filter_by(user_id=session['user_id']).order_by(LearningMaterial.created_at.desc()).all()
    return render_template('list_materials.html', materials=materials)

@app.route('/material/<int:material_id>')
@login_required
def view_material(material_id):
    """View the content of a material and offer to generate a quiz from it."""
    material = LearningMaterial.query.filter_by(id=material_id, user_id=session['user_id']).first_or_404()
    return render_template('view_material.html', material=material)


# --- Quiz Routes ---

@app.route('/quiz')
@login_required
def quiz():
    # Check if generating from a specific material
    material_id = request.args.get('material_id')
    material_topic = "General Knowledge" # Default topic
    material_id_to_pass = None # Ensure None if not valid

    if material_id:
        try:
             material_id_int = int(material_id)
             material = LearningMaterial.query.filter_by(id=material_id_int, user_id=session['user_id']).first()
             if material:
                 material_topic = material.title
                 material_id_to_pass = material_id_int # Valid ID found
             else:
                  flash("Material not found or doesn't belong to you.", "warning")
        except ValueError:
             flash("Invalid material ID provided.", "warning")

    # Pass material_id_to_pass (which is None if invalid/not found)
    return render_template('quiz.html', material_id=material_id_to_pass, material_topic=material_topic)


@app.route('/api/test-groq')
def test_groq():
    """Test endpoint to verify Groq API is configured correctly"""
    try:
        # Use the centralized function which includes checks
        groq_client = get_groq_client()

        # Test with a simple request
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You respond concisely."},
                {"role": "user", "content": "Reply with the single word: OK"}
            ],
            max_tokens=8,
            temperature=0.0
        )

        return jsonify({
            'success': True,
            'message': 'Groq API is configured correctly and reachable!',
            'test_response': response.choices[0].message.content.strip()
        })

    except ValueError as ve: # Catch specific error from get_groq_client
       return jsonify({
            'success': False,
            'message': f'Groq API configuration error: {str(ve)}',
            'help': 'Please create a .env file in the root directory with GROQ_API_KEY=your_actual_key'
       }), 500
    except Exception as e:
       return jsonify({
            'success': False,
            'message': f'Groq API test failed: {str(e)}',
            'error_type': type(e).__name__
       }), 500

@app.route('/api/generate-quiz', methods=['POST'])
@login_required
def generate_quiz():
    data = request.get_json()
    if not data:
         return jsonify({'success': False, 'message': 'Invalid request payload.'}), 400

    topic = data.get('topic', 'General Knowledge').strip()
    try:
         num_questions = int(data.get('num_questions', 10))
    except (ValueError, TypeError):
         return jsonify({'success': False, 'message': 'Number of questions must be an integer.'}), 400

    difficulty = str(data.get('difficulty', 'mixed')).lower().strip()

    # Validate num_questions range
    num_questions = min(max(num_questions, 5), 30) # Reduced max slightly for stability

    # Validate difficulty
    if difficulty not in ['easy', 'medium', 'hard', 'mixed']:
        difficulty = 'mixed'

    # [MODULE 2] Check for context from uploaded material
    material_id = data.get('material_id') # Can be None or empty string
    context_text = None
    if material_id:
        try:
            material_id_int = int(material_id)
            material = LearningMaterial.query.filter_by(id=material_id_int, user_id=session['user_id']).first()
            if material:
                context_text = material.content
                # Override topic only if using material
                topic = material.title
                print(f"[v1][INFO] Generating quiz from material: {material.title} (ID: {material_id_int})")
            else:
                 print(f"[v1][WARN] Material ID {material_id_int} provided but not found for user {session['user_id']}.")
                 # Proceed without context, using the topic from the request
        except (ValueError, TypeError):
             print(f"[v1][WARN] Invalid material_id received: {material_id}. Proceeding without context.")


    try:
        # Centralized client getting with checks
        groq_client = get_groq_client()

        print(f"[v1][INFO] Generating quiz request: topic='{topic}', questions={num_questions}, difficulty='{difficulty}', context_present={bool(context_text)}")

        # Simplified to one batch for potentially better reliability with smaller counts
        batch_count = num_questions
        distribution = choose_type_distribution(batch_count)

        # [MODULE 3] Use the modified build_prompt
        prompt = build_prompt(topic, batch_count, difficulty, distribution, context_text)

        print(f"[v1][INFO] Sending request for {batch_count} questions...")
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant", # Or try "mixtral-8x7b-32768" if JSON is inconsistent
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5, # Slightly lower temp might help JSON structure
            max_tokens=4096, # Increased max_tokens
        )
        content = response.choices[0].message.content or ""
        print(f"[v1][DEBUG] Raw Groq response preview: {content[:300]}...")

        items = extract_json_array(content)

        if items is None:
            print(f"[v1][ERROR] JSON extraction failed. Raw content: {content}")
            # Try to find common non-JSON text issues
            if "```json" in content or "```" in content:
                 error_detail = "AI response contained markdown formatting around the JSON."
            elif not content.strip().startswith("["):
                 error_detail = "AI response did not start with a JSON array."
            else:
                 error_detail = "Could not parse JSON structure from AI response."
            return jsonify({
                'success': False,
                'message': f'Failed to parse quiz data from AI. {error_detail} Please try reducing questions or simplifying the topic.'
            }), 500

        cleaned = sanitize_items(items)
        print(f"[v1][INFO] Parsed and sanitized {len(cleaned)} valid questions.")

        all_items = dedupe_by_question(cleaned)
        print(f"[v1][INFO] Deduplicated to {len(all_items)} unique questions.")

        if len(all_items) < min(5, num_questions): # Ensure at least 5 or requested number if less
            print(f"[v1][ERROR] Generated too few valid questions: {len(all_items)} (requested {num_questions})")
            return jsonify({
                'success': False,
                'message': f'AI generated too few valid questions ({len(all_items)}). Please try again, perhaps with a different topic or fewer questions.'
            }), 500

        # Trim if we got more than requested
        if len(all_items) > num_questions:
            all_items = all_items[:num_questions]

        print(f"[v1][SUCCESS] Final generated quiz: {len(all_items)} questions for topic '{topic}'")
        return jsonify({
            'success': True,
            'quiz': all_items,
            'topic': topic # Return the final topic used (could be from material)
        })

    except ValueError as ve: # Catch API key config errors from get_groq_client
       print(f"[v1][ERROR] Configuration error: {str(ve)}")
       return jsonify({'success': False, 'message': str(ve)}), 500
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        print(f"[v1][ERROR] Unexpected error in /api/generate-quiz: {error_type}: {error_msg}")
        # Log the full traceback to the console for detailed debugging
        import traceback
        traceback.print_exc()

        user_message = f'An unexpected server error occurred ({error_type}). Please try again later.'
        if 'rate' in error_msg.lower() or 'limit' in error_msg.lower():
             user_message = 'Rate limit exceeded. Please wait a moment and try again.'
        elif 'network' in error_msg.lower() or 'connection' in error_msg.lower():
             user_message = 'Network error contacting AI service. Please check your connection and try again.'

        return jsonify({
            'success': False,
            'message': user_message,
            'error_type': error_type
        }), 500


@app.route('/api/save-attempt', methods=['POST'])
@login_required
def save_attempt():
    data = request.get_json() or {}
    topic = data.get('topic')
    score = data.get('score')
    total_questions = data.get('total_questions')
    answers = data.get('answers', []) # Expecting list of answer details from quiz.js

    print(f"[DEBUG] save_attempt received: topic='{topic}', score={score}, total_questions={total_questions}, answers_count={len(answers)}")

    if not topic or score is None or total_questions is None or not isinstance(answers, list):
        print(f"[v1][ERROR] Invalid payload received in save_attempt: {data}")
        return jsonify({'success': False, 'message': 'Invalid payload structure.'}), 400

    try:
        score_int = int(score)
        total_questions_int = int(total_questions)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Score and total questions must be integers.'}), 400


    try:
        attempt = QuizAttempt(
            user_id=session['user_id'],
            topic=str(topic)[:100], # Limit topic length
            score=score_int,
            total_questions=total_questions_int
        )
        db.session.add(attempt)
        db.session.flush()  # Get attempt.id before adding answers

        saved_answers_count = 0
        for a in answers:
            # Add more validation for each answer's structure
            if not isinstance(a, dict) or 'question' not in a or 'evaluation' not in a:
                print(f"[v1][WARN] Skipping malformed answer entry in save_attempt: {a}")
                continue

            try:
                question = a.get('question', {})
                evaluation = a.get('evaluation', {})
                feedback = a.get('feedback', {}) # Feedback object from frontend
                
                # Basic validation of inner structures
                if not isinstance(question, dict) or not isinstance(evaluation, dict):
                    print(f"[v1][WARN] Skipping answer with malformed inner structure: {a}")
                    continue

                qa = QuizAnswer(
                    attempt_id=attempt.id,
                    question_text=str(question.get('question', 'Missing Question Text'))[:10000],
                    question_type=str(question.get('question_type', 'unknown'))[:32],
                    # Safely handle options and answers serialization
                    options_json=json.dumps(question.get('options')) if question.get('options') is not None else None,
                    correct_answer_json=json.dumps(evaluation.get('correct_answer')), # Correct answer from evaluation
                    user_answer_json=json.dumps(a.get('user_answer')), # User's raw answer
                    is_correct=bool(evaluation.get('is_correct', False)),
                    # Combine feedback sources, prioritize feedback obj, then question obj
                    explanation=str(feedback.get('explanation') or question.get('explanation') or 'No explanation available.')[:10000],
                    time_spent_seconds=int(a.get('time_spent') or 0)
                )
                db.session.add(qa)
                saved_answers_count += 1
            except Exception as inner_ex:
                # Log error for the specific answer but continue with others
                print(f"[v1][ERROR] Failed to save individual answer {a.get('question', {}).get('question', 'N/A')}: {inner_ex}")
                continue # Skip this answer

        db.session.commit()
        print(f"[v1][INFO] Saved attempt ID {attempt.id} with {saved_answers_count}/{len(answers)} answers for user {session['user_id']}. Topic: '{topic}'")
        return jsonify({'success': True, 'message': f'Quiz attempt saved successfully for topic: {topic}', 'attempt_id': attempt.id})

    except Exception as e:
        db.session.rollback() # Rollback the whole transaction on major error
        print(f"[v1][ERROR] Failed to save quiz attempt: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to save quiz attempt due to a server error.'}), 500


@app.route('/api/history')
@login_required
def get_history():
    try:
        attempts = QuizAttempt.query.filter_by(user_id=session['user_id']).order_by(QuizAttempt.completed_at.desc()).limit(10).all()

        history = [{
            'topic': attempt.topic,
            'score': attempt.score,
            'total': attempt.total_questions,
            'percentage': round((attempt.score / attempt.total_questions) * 100, 1) if attempt.total_questions > 0 else 0,
            'date': attempt.completed_at.strftime('%Y-%m-%d %H:%M')
        } for attempt in attempts]

        return jsonify({'success': True, 'history': history})
    except Exception as e:
       print(f"[v1][ERROR] Error fetching history: {e}")
       return jsonify({'success': False, 'message': 'Could not retrieve quiz history.'}), 500


@app.route('/api/evaluate-answer', methods=['POST'])
@login_required
def evaluate_answer_endpoint():
    data = request.get_json()
    question = data.get('question')
    user_answer = data.get('user_answer') # Can be string, int, list, bool

    if not isinstance(question, dict) or user_answer is None: # Check question is dict
        return jsonify({'success': False, 'message': 'Invalid question or answer format.'}), 400

    try:
        # Assuming evaluate_answer and generate_feedback are robust
        evaluation_result = evaluate_answer(question, user_answer)
        feedback = generate_feedback(question, evaluation_result)

        return jsonify({
            'success': True,
            'evaluation': evaluation_result,
            'feedback': feedback,
        })

    except Exception as e:
        print(f"[v1][ERROR] Error in evaluate_answer_endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Error evaluating answer: {str(e)}'
        }), 500


# --- [MODULE 4] Adaptive Learning Engine ---
@app.route('/api/update-difficulty', methods=['POST'])
@login_required
def update_difficulty_endpoint():
    data = request.get_json()
    performance_history = data.get('performance_history', [])
    current_difficulty = data.get('current_difficulty', 'medium')

    if not isinstance(performance_history, list):
         return jsonify({'success': False, 'message': 'Performance history must be a list.'}), 400

    try:
        new_difficulty = update_difficulty(performance_history, current_difficulty)

        return jsonify({
            'success': True,
            'recommended_difficulty': new_difficulty,
            'difficulty_changed': new_difficulty != current_difficulty
        })

    except Exception as e:
        print(f"[v1][ERROR] Error updating difficulty: {e}")
        return jsonify({
            'success': False,
            'message': f'Error updating difficulty: {str(e)}'
        }), 500

@app.route('/api/recommend-type', methods=['POST'])
@login_required
def recommend_type_endpoint():
    """
    [MODULE 4] Stubbed endpoint to recommend the next question type
    based on user's performance history.
    """
    data = request.get_json()
    performance_history = data.get('performance_history', []) # List of booleans

    # Stubbed logic (same as before)
    if len(performance_history) < 3:
        recommended_type = "mcq_single" # Start with basics
    else:
        # Look at last 3 answers
        recent_correct = sum(1 for passed in performance_history[-3:] if passed)
        if recent_correct == 3: # All correct -> harder
            recommended_type = "short_answer"
        elif recent_correct == 0: # All incorrect -> easier
            recommended_type = "true_false"
        else: # Mixed -> default
            recommended_type = "mcq_single"

    return jsonify({
        'success': True,
        'recommended_type': recommended_type
    })


# --- Helper functions ---

def extract_json_array(text: str) -> Optional[List[Dict[str, Any]]]:
    if not text: return None
    text = text.strip()
    # Remove markdown fences first
    text = re.sub(r"^\s*```(?:json)?\s*", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"\s*```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    # Normalize quotes
    text = (text
            .replace("\u201c", '"').replace("\u201d", '"')
            .replace("\u2018", "'").replace("\u2019", "'"))

    # Find the main array structure
    start = text.find('[')
    end = -1
    if start != -1:
        depth = 0
        in_string = False
        string_char = ''
        escaped = False
        for i, ch in enumerate(text[start:], start=start):
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                escaped = True
                continue

            if ch in ('"', "'"):
                if in_string and ch == string_char:
                    in_string = False
                elif not in_string:
                    in_string = True
                    string_char = ch
                continue # Skip bracket counting inside strings

            if not in_string:
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break

    if start != -1 and end != -1:
        candidate = text[start : end + 1]
    else:
        # Fallback: find first '[' and last ']' if bracket matching failed
        first_bracket = text.find('[')
        last_bracket = text.rfind(']')
        if first_bracket != -1 and last_bracket > first_bracket:
             candidate = text[first_bracket : last_bracket + 1]
        else:
             print("[v1][DEBUG] extract_json_array: Could not find valid array structure.")
             return None # No plausible array found

    # Remove trailing commas before closing braces/brackets more aggressively
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    # Remove trailing comma at the very end if exists
    candidate = re.sub(r",\s*$", "", candidate)

    try:
        data = json.loads(candidate)
        if isinstance(data, list):
            return data
        # Handle cases where the LLM might return a single dict instead of a list
        elif isinstance(data, dict) and 'quiz' in data and isinstance(data['quiz'], list):
             print("[v1][WARN] extract_json_array: LLM returned a dict with 'quiz' key, extracting list.")
             return data['quiz']
        elif isinstance(data, dict):
             print("[v1][WARN] extract_json_array: LLM returned a single dict, wrapping in list.")
             return [data] # Wrap single object in a list if it looks like a question
        else:
             print(f"[v1][DEBUG] extract_json_array: Parsed data is not a list or expected dict: {type(data)}")
             return None
    except json.JSONDecodeError as e:
        print(f"[v1][ERROR] extract_json_array: Final JSON parse failed: {e}. Candidate was: {candidate[:500]}...")
        return None

def sanitize_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sanitized: List[Dict[str, Any]] = []
    if not isinstance(items, list): # Basic check
         print("[v1][WARN] sanitize_items: input 'items' was not a list.")
         return []

    for item_index, it in enumerate(items):
        if not isinstance(it, dict):
            print(f"[v1][WARN] sanitize_items: Skipping non-dict item at index {item_index}.")
            continue
        try:
            question_text = str(it.get("question", "")).strip()
            if not question_text:
                print(f"[v1][WARN] sanitize_items: Skipping item {item_index} due to empty question text.")
                continue

            question_type = str(it.get("question_type", "mcq")).strip().lower()
            explanation = str(it.get("explanation", "")).strip()
            if len(explanation) > 2000:
                explanation = explanation[:1997] + "..."

            difficulty = str(it.get("difficulty_level", "medium")).lower()
            if difficulty not in ['easy', 'medium', 'hard']: # Simplified list
                difficulty = 'medium' # Default

            # --- MCQ Single ---
            if question_type in ["mcq", "mcq_single"]:
                options_raw = it.get("options")
                if not isinstance(options_raw, list) or len(options_raw) < 2:
                     print(f"[v1][WARN] sanitize_items: Skipping MCQ (single) item {item_index} due to invalid options: {options_raw}")
                     continue
                options = [str(o).strip() for o in options_raw if str(o).strip()][:4] # Max 4
                if len(options) < 2: # Need at least two
                     print(f"[v1][WARN] sanitize_items: Skipping MCQ (single) item {item_index} due to < 2 valid options.")
                     continue
                while len(options) < 4: options.append(f"Option {len(options)+1}") # Pad to 4

                ca_raw = it.get("correct_answer")
                ca = 0 # Default
                try:
                     ca = int(ca_raw)
                except (ValueError, TypeError):
                    if isinstance(ca_raw, str):
                        try: ca = options.index(ca_raw.strip())
                        except ValueError: ca = 0 # Fallback
                    else: ca = 0 # Fallback
                ca = max(0, min(len(options) - 1, ca)) # Clamp index

                sanitized.append({
                    "question": question_text, "question_type": "mcq_single",
                    "options": options, "correct_answer": ca,
                    "explanation": explanation or "No explanation provided.",
                    "difficulty_level": difficulty
                })

            # --- MCQ Multiple ---
            elif question_type == "mcq_multiple":
                options_raw = it.get("options")
                if not isinstance(options_raw, list) or len(options_raw) < 2:
                     print(f"[v1][WARN] sanitize_items: Skipping MCQ (multi) item {item_index} due to invalid options.")
                     continue
                options = [str(o).strip() for o in options_raw if str(o).strip()][:4] # Max 4
                if len(options) < 2:
                     print(f"[v1][WARN] sanitize_items: Skipping MCQ (multi) item {item_index} due to < 2 valid options.")
                     continue
                while len(options) < 4: options.append(f"Option {len(options)+1}")

                ca_raw = it.get("correct_answer")
                indices = []
                if isinstance(ca_raw, list):
                    for v in ca_raw:
                        try: idx = int(v)
                        except (ValueError, TypeError):
                           if isinstance(v, str):
                                try: idx = options.index(v.strip())
                                except ValueError: continue # Ignore if text doesn't match
                           else: continue # Ignore non-int, non-str in list
                        if 0 <= idx < len(options): indices.append(idx)
                elif isinstance(ca_raw, (int, str)): # Handle single answer provided for multi
                    try: idx = int(ca_raw)
                    except (ValueError, TypeError):
                         if isinstance(ca_raw, str):
                             try: idx = options.index(ca_raw.strip())
                             except ValueError: idx = -1 # Not found
                         else: idx = -1 # Not int or str
                    if 0 <= idx < len(options): indices = [idx]

                indices = sorted(list(set(indices))) # Dedupe and sort
                if not indices: # Must have at least one correct answer
                     print(f"[v1][WARN] sanitize_items: Skipping MCQ (multi) item {item_index} due to no valid correct answers.")
                     continue

                sanitized.append({
                    "question": question_text, "question_type": "mcq_multiple",
                    "options": options, "correct_answer": indices,
                    "explanation": explanation or "No explanation provided.",
                    "difficulty_level": difficulty
                })

            # --- True/False ---
            elif question_type == "true_false":
                ca_raw = it.get("correct_answer")
                ca_bool = None
                if isinstance(ca_raw, bool): ca_bool = ca_raw
                elif isinstance(ca_raw, str):
                    ca_str = ca_raw.strip().lower()
                    if ca_str in ["true", "t", "1", "yes", "correct"]: ca_bool = True
                    elif ca_str in ["false", "f", "0", "no", "incorrect"]: ca_bool = False
                elif isinstance(ca_raw, int):
                    if ca_raw == 1: ca_bool = True
                    elif ca_raw == 0: ca_bool = False
                if ca_bool is None:
                     print(f"[v1][WARN] sanitize_items: Skipping T/F item {item_index} due to uninterpretable answer: {ca_raw}")
                     continue

                sanitized.append({
                    "question": question_text, "question_type": "true_false",
                    "correct_answer": ca_bool,
                    "explanation": explanation or "No explanation provided.",
                    "difficulty_level": difficulty
                })

            # --- Short Answer / Fill-in-the-Blank ---
            elif question_type in ["short_answer", "fill_in_the_blank"]:
                # Keep original type
                if question_type == "fill_in_the_blank" and "___" not in question_text and "[BLANK]" not in question_text:
                     print(f"[v1][WARN] sanitize_items: Item {item_index} 'fill_in_the_blank' lacks '___' or '[BLANK]'.")

                expected_raw = it.get("correct_answer")
                if expected_raw is None:
                     print(f"[v1][WARN] sanitize_items: Skipping {question_type} item {item_index} due to missing correct answer.")
                     continue
                expected = str(expected_raw).strip()
                if not expected:
                     print(f"[v1][WARN] sanitize_items: Skipping {question_type} item {item_index} due to empty correct answer.")
                     continue

                sanitized.append({
                    "question": question_text, "question_type": question_type, # Use original type
                    "correct_answer": expected,
                    "explanation": explanation or "No explanation provided.",
                    "difficulty_level": difficulty
                })
            else:
                 print(f"[v1][WARN] sanitize_items: Skipping item {item_index} due to unknown type: '{question_type}'")

        except Exception as e:
            print(f"[v1][ERROR] sanitize_items: Unexpected error on item {item_index}: {e}. Item: {it}")
            import traceback; traceback.print_exc()
            continue # Skip problematic item
    return sanitized

def dedupe_by_question(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result: List[Dict[str, Any]] = []
    for it in items:
        # Use a simplified version of the question text for deduplication
        q_norm = normalize_text(it.get("question", "")) # Use global helper
        if q_norm and q_norm not in seen:
            seen.add(q_norm)
            result.append(it)
    return result

def build_prompt(topic: str, count: int, difficulty: str, distribution: Dict[str, int], context: Optional[str] = None) -> str:
    difficulty_line = "" if difficulty == 'mixed' else f"Overall difficulty level should be around: {difficulty.capitalize()}.\n"
    context_line = ""
    if context:
        context_preview = json.dumps(context[:2500]) # Use json.dumps for safety
        context_line = f"Generate questions BASED **SOLELY** ON THE FOLLOWING TEXTUAL CONTEXT:\n<context>\n{context_preview}\n</context>\n\n"

    mcq_s = distribution.get("mcq_single", 0)
    mcq_m = distribution.get("mcq_multiple", 0)
    tf = distribution.get("true_false", 0)
    sa = distribution.get("short_answer", 0)
    fib = distribution.get("fill_in_the_blank", 0)

    total_requested = mcq_s + mcq_m + tf + sa + fib
    if count > 0 and total_requested == 0:
         mcq_s = count # Default to MCQ if distribution failed

    return f"""Please generate exactly {count} quiz questions about the topic "{topic}".
{context_line}
Strictly adhere to the following distribution of question types:
- Multiple Choice (single correct answer): {mcq_s} questions (type: "mcq_single")
- Multiple Choice (multiple correct answers): {mcq_m} questions (type: "mcq_multiple")
- True/False: {tf} questions (type: "true_false")
- Short Answer: {sa} questions (type: "short_answer")
- Fill-in-the-Blank: {fib} questions (type: "fill_in_the_blank")

**Output Format:** Respond **ONLY** with a valid JSON array of question objects. Do not include any text before or after the JSON array. Do not use markdown code fences (like ```json).

Each object in the JSON array must follow this exact schema:
{{
  "question": "The full text of the question?",
  "question_type": "(must be one of: mcq_single, mcq_multiple, true_false, short_answer, fill_in_the_blank)",
  "options": ["Option A", "Option B", "Option C", "Option D"],  // REQUIRED for mcq_single and mcq_multiple ONLY. Exactly 4 options.
  "correct_answer": (value depends on question_type), // mcq_single: index (0-3), mcq_multiple: array of indices [1, 3], true_false: boolean (true/false), short_answer/fill_in_the_blank: string
  "explanation": "A concise explanation (around 50-100 words) justifying the correct answer and explaining relevant concepts.",
  "difficulty_level": "(must be one of: easy, medium, hard)" // Estimate difficulty.
}}

**Specific Rules:**
1.  **JSON ONLY:** The entire response must be a single JSON array `[...]`.
2.  **Schema Compliance:** Every field is mandatory (except 'options' for non-MCQ types).
3.  **MCQ Options:** MCQs must have exactly 4 distinct string options.
4.  **Fill-in-the-Blank:** The "question" text for "fill_in_the_blank" *must* contain a placeholder like '___' or '[BLANK]'.
5.  **Correct Answers:** Ensure `correct_answer` format matches `question_type`. For `mcq_multiple`, provide an array even if only one answer is correct (e.g., `[2]`). For `true_false`, use actual booleans `true` or `false`.
6.  **Explanations:** Provide clear and helpful explanations.
7.  **Difficulty:** Assign a reasonable `easy`, `medium`, or `hard` level. {difficulty_line}
8.  **Context:** If context was provided, base questions *strictly* on that text.

Generate the JSON array now.
"""

def choose_type_distribution(count: int) -> Dict[str, int]:
    if count <= 0: return {}
    # Use the weights from your provided code
    weights = {
        "mcq_single": 0.50,
        "true_false": 0.15,
        "fill_in_the_blank": 0.15,
        "short_answer": 0.10,
        "mcq_multiple": 0.40, # Your updated weight
    }
    
    # Normalize weights in case they don't sum to 1.0 (like yours, which sum to 1.3)
    total_weight = sum(weights.values())
    if total_weight == 0: return {"mcq_single": count} # Fallback
    
    alloc = {k: int(round(count * (w / total_weight))) for k, w in weights.items()}

    current_sum = sum(alloc.values())
    delta = count - current_sum

    order = ["mcq_single", "mcq_multiple", "true_false", "fill_in_the_blank", "short_answer"] # Prioritize MCQs
    if delta > 0:
        for i in range(delta): alloc[order[i % len(order)]] += 1
    elif delta < 0:
        for key in reversed(order):
            while delta < 0 and alloc[key] > 0:
                alloc[key] -= 1; delta += 1
    
    # Final check
    final_sum = sum(alloc.values())
    if final_sum != count:
        alloc['mcq_single'] += (count - final_sum)

    return {k: v for k, v in alloc.items() if v > 0} # Filter zero-count types


# --- Global Helper Functions ---
def normalize_text(s: str) -> str:
    """Lowercase, strip, and collapse whitespace."""
    return re.sub(r'\s+', ' ', str(s).strip().lower())

def similarity(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return difflib.SequenceMatcher(None, a, b).ratio()
# --- End Helper Functions ---


def evaluate_answer(question: Dict[str, Any], user_answer: Any) -> Dict[str, Any]:
    """
    Evaluates the user's answer against the correct answer.
    This is the complete and correct version.
    """
    question_type = str(question.get('question_type', 'mcq_single')).strip().lower()
    correct_answer = question.get('correct_answer') # Ground truth

    # Default result structure
    result = {
        'is_correct': False,
        'feedback': 'Evaluation failed.',
        'question_type': question_type,
        'correct_answer': correct_answer,
        'user_answer_parsed': user_answer
    }

    try:
        # --- MCQ Single Choice ---
        if question_type in ['mcq', 'mcq_single']:
            options = question.get('options', [])
            user_index = -1; correct_index = -1
            try: user_index = int(user_answer)
            except (ValueError, TypeError, AttributeError): pass
            try: correct_index = int(correct_answer)
            except (ValueError, TypeError, AttributeError): pass

            result['user_answer_parsed'] = user_index
            result['correct_answer'] = correct_index

            if user_index == correct_index and 0 <= correct_index < len(options):
                result['is_correct'] = True
                result['feedback'] = "Correct!"
            elif 0 <= correct_index < len(options):
                 result['feedback'] = f"Incorrect. The correct answer was {chr(65 + correct_index)}: {options[correct_index]}"
            else:
                 result['feedback'] = "Incorrect. Could not determine the correct option."

        # --- MCQ Multiple Choice ---
        elif question_type == 'mcq_multiple':
             options = question.get('options', [])
             user_indices = []
             if isinstance(user_answer, list):
                 for ans in user_answer:
                     try: idx = int(ans);
                     except (ValueError, TypeError): continue
                     if 0 <= idx < len(options): user_indices.append(idx)
             user_indices = sorted(list(set(user_indices)))
             result['user_answer_parsed'] = user_indices

             correct_indices = []
             if isinstance(correct_answer, list):
                 for ans in correct_answer:
                      try: idx = int(ans)
                      except (ValueError, TypeError): continue
                      if 0 <= idx < len(options): correct_indices.append(idx)
             correct_indices = sorted(list(set(correct_indices)))
             result['correct_answer'] = correct_indices

             if user_indices == correct_indices and correct_indices:
                 result['is_correct'] = True
                 result['feedback'] = "Correct!"
             else:
                 pretty_correct = ', '.join(chr(65 + i) for i in correct_indices)
                 result['feedback'] = f"Incorrect. The correct option(s) were: {pretty_correct}" if pretty_correct else "Incorrect."

        # --- True/False ---
        elif question_type == 'true_false':
            user_bool = None
            if isinstance(user_answer, bool): user_bool = user_answer
            elif isinstance(user_answer, str):
                user_str = user_answer.strip().lower()
                if user_str in ['true', 't', '1', 'yes']: user_bool = True
                elif user_str in ['false', 'f', '0', 'no']: user_bool = False
            result['user_answer_parsed'] = user_bool

            correct_bool = None
            if isinstance(correct_answer, bool): correct_bool = correct_answer
            elif isinstance(correct_answer, str):
                 correct_str = correct_answer.strip().lower()
                 if correct_str == 'true': correct_bool = True
                 elif correct_str == 'false': correct_bool = False
            elif isinstance(correct_answer, int):
                 correct_bool = (correct_answer == 1)
            result['correct_answer'] = correct_bool

            if user_bool == correct_bool and correct_bool is not None:
                result['is_correct'] = True
                result['feedback'] = "Correct!"
            elif correct_bool is not None:
                 result['feedback'] = f"Incorrect. The correct answer was: {'True' if correct_bool else 'False'}"
            else:
                 result['feedback'] = "Incorrect. Could not determine correct answer."

        # --- Short Answer & Fill in the Blank ---
        elif question_type in ['short_answer', 'fill_in_the_blank']:
            # Uses GLOBAL helper functions
            if not isinstance(user_answer, str) or correct_answer is None:
                 result['feedback'] = f"Incorrect. Expected text. Correct: {correct_answer}"
            else:
                user_norm = normalize_text(user_answer)
                correct_norm = normalize_text(str(correct_answer))
                sim = similarity(user_norm, correct_norm)
                threshold = 0.85 # Similarity threshold
                is_correct = sim >= threshold
                result['is_correct'] = is_correct
                result['similarity'] = round(sim, 3)

                if is_correct:
                    result['feedback'] = "Correct!"
                elif sim > 0.6:
                    result['feedback'] = f"Close! The expected answer was: '{correct_answer}'"
                else:
                    result['feedback'] = f"Incorrect. The expected answer was: '{correct_answer}'"

        # --- Unknown Type ---
        else:
            result['feedback'] = f"Cannot evaluate unknown question type: {question_type}"

    except Exception as e:
       print(f"[v1][ERROR] Exception during evaluate_answer: {e}")
       result['feedback'] = f"An error occurred during evaluation: {e}"
       result['is_correct'] = False # Ensure correctness is false on error

    return result

def generate_feedback(question: Dict[str, Any], evaluation_result: Dict[str, Any]) -> Dict[str, Any]:
    is_correct = evaluation_result.get('is_correct', False)
    explanation = question.get('explanation', 'No explanation provided.')
    status_icon = "✅" if is_correct else "❌"
    status_text = "Correct!" if is_correct else "Incorrect"
    hint = ""
    if not is_correct:
        hint = f"💡 {evaluation_result.get('feedback', 'Check the correct answer.')}"
    return {
        'status_icon': status_icon, 'status_text': status_text,
        'explanation': explanation, 'hint': hint, 'is_correct': is_correct
    }

def update_difficulty(performance_history: List[bool], current_difficulty: str) -> str:
    # Use the 3-correct / 2-incorrect streak logic
    new_difficulty = current_difficulty
    history_len = len(performance_history)

    if history_len >= 3 and all(performance_history[-3:]): # 3 correct streak
        if current_difficulty == 'easy': new_difficulty = 'medium'; print("[v1] ADAPT: Easy -> Medium")
        elif current_difficulty == 'medium': new_difficulty = 'hard'; print("[v1] ADAPT: Medium -> Hard")
    elif history_len >= 2 and not any(performance_history[-2:]): # 2 incorrect streak
        if current_difficulty == 'hard': new_difficulty = 'medium'; print("[v1] ADAPT: Hard -> Medium")
        elif current_difficulty == 'medium': new_difficulty = 'easy'; print("[v1] ADAPT: Medium -> Easy")

    return new_difficulty

# --- Short Answer Grading ---
def build_short_answer_prompt(question_text: str, expected_answer: str, student_answer: str, threshold: int = 60) -> str:
     return (
        "You are a fair grading assistant for short answers.\n"
        "Compare the student's answer to the expected answer based on meaning and key terms.\n"
        "Return **ONLY** valid JSON with keys: {\"yes_no\": \"Yes|No\", \"score\": 0-100, \"explanation\": \"Brief reason for score.\"}.\n"
        f"Question: {question_text}\n"
        f"Expected Answer: {expected_answer}\n"
        f"Student Answer: {student_answer}\n"
        f"Consider the student answer correct ('Yes') if it captures the core meaning. Score >= {threshold} means 'Yes'."
     )

def groq_grade_short_answer(question_text: str, expected_answer: str, student_answer: str, threshold: int = 60) -> Dict[str, Any]:
    default_result = {'yes_no': 'No', 'score': 0, 'explanation': 'AI grading failed or unavailable.'}
    try:
        groq_client = get_groq_client()
    except ValueError as e:
        print(f"[v1][WARN] groq_grade_short_answer: Cannot get Groq client ({e}), falling back.")
        # Fallback uses GLOBAL functions
        user_norm = normalize_text(student_answer)
        exp_norm = normalize_text(expected_answer)
        sim = similarity(user_norm, exp_norm)
        score = int(round(sim * 100))
        return { 'yes_no': 'Yes' if score >= threshold else 'No', 'score': score, 'explanation': f'Local similarity fallback ({round(sim, 2)})' }

    prompt = build_short_answer_prompt(question_text, expected_answer, student_answer, threshold)
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant", messages=[{"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=150,
        )
        content = (response.choices[0].message.content or '').strip()
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            try:
                obj = json.loads(json_match.group(0))
                yes_no = str(obj.get('yes_no', 'No')).strip().lower()
                score = int(obj.get('score', 0))
                explanation = str(obj.get('explanation', 'No explanation.')).strip()[:300]
                score = max(0, min(100, score))
                final_yes_no = 'Yes' if (yes_no in ['yes', 'y', 'true', '1'] or score >= threshold) else 'No'
                return { 'yes_no': final_yes_no, 'score': score, 'explanation': explanation }
            except (json.JSONDecodeError, ValueError, TypeError) as parse_err:
                 print(f"[v1][ERROR] groq_grade_short_answer: Parse failed: {parse_err}. Content: {content}")
                 return default_result
        else:
            print(f"[v1][ERROR] groq_grade_short_answer: No JSON object found. Content: {content}")
            return default_result
    except Exception as api_err:
        print(f"[v1][ERROR] groq_grade_short_answer: API call failed: {api_err}")
        return default_result

@app.route('/api/grade-short-answer', methods=['POST'])
@login_required
def grade_short_answer():
    data = request.get_json()
    question = data.get('question', '')
    expected = data.get('expected_answer', '')
    student = data.get('student_answer', '')
    threshold = int(data.get('threshold', 75)) # AI grader threshold

    if not question or not expected or student is None:
        return jsonify({'success': False, 'message': 'Missing question, expected answer, or student answer'}), 400

    # 1. Try fast local evaluation first
    local_eval = evaluate_answer( {"question_type": "short_answer", "correct_answer": expected}, student )
    if local_eval['is_correct']:
        print("[v1][INFO] Short answer graded as correct by local similarity.")
        return jsonify({'success': True, 'result': {
            'yes_no': 'Yes',
            'score': int(local_eval.get('similarity', 1.0) * 100),
            'explanation': 'Local similarity check passed.'
        }})

    # 2. If local eval fails, use AI grader
    print("[v1][INFO] Local similarity check failed or borderline, escalating to Groq...")
    ai_result = groq_grade_short_answer(question, expected, student, threshold)
    return jsonify({'success': True, 'result': ai_result})

# --- Analytics Routes ---
@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/api/analytics/summary')
@login_required
def analytics_summary():
    user_id = session['user_id']
    try:
        attempts = QuizAttempt.query.filter_by(user_id=user_id).all()
        if not attempts:
            return jsonify({'success': True, 'data': {'total_quizzes': 0, 'total_questions': 0, 'accuracy': 0, 'avg_time': 0}})

        total_quizzes = len(attempts)
        total_questions_attempted = sum(attempt.total_questions for attempt in attempts)
        total_correct = sum(attempt.score for attempt in attempts)
        accuracy = round((total_correct / total_questions_attempted * 100) if total_questions_attempted > 0 else 0, 1)

        total_time_all_questions = db.session.query(db.func.sum(QuizAnswer.time_spent_seconds)).join(QuizAttempt).filter(QuizAttempt.user_id == user_id).scalar() or 0
        total_questions_answered_db = db.session.query(db.func.count(QuizAnswer.id)).join(QuizAttempt).filter(QuizAttempt.user_id == user_id).scalar() or 0
        avg_time = round((total_time_all_questions / total_questions_answered_db) if total_questions_answered_db > 0 else 0, 1)

        return jsonify({'success': True, 'data': {
            'total_quizzes': total_quizzes, 'total_questions': total_questions_attempted,
            'accuracy': accuracy, 'avg_time': avg_time,
        }})
    except Exception as e:
        print(f"[v1][ERROR] Error in analytics_summary: {e}"); return jsonify({'success': False, 'message': 'Could not load summary data.'}), 500

@app.route('/api/analytics/attempts')
@login_required
def analytics_attempts():
    user_id = session['user_id']
    try:
        # Query params
        page = int(request.args.get('page', 1))
        per_page = min(max(int(request.args.get('per_page', 20)), 1), 50)
        sort_by = (request.args.get('sort_by') or 'date').lower()
        order = (request.args.get('order') or 'desc').lower()
        topic_filter = (request.args.get('topic') or '').strip()

        query = QuizAttempt.query.filter_by(user_id=user_id)

        if topic_filter:
            query = query.filter(QuizAttempt.topic.ilike(f"%{topic_filter}%"))

        # Sorting
        if sort_by in ['topic', 'score', 'total_questions']:
            sort_col = getattr(QuizAttempt, sort_by)
        elif sort_by in ['percentage', 'grade']:
            # derive via score/total; fallback to date order after fetching
            sort_col = QuizAttempt.completed_at
        else:
            # date
            sort_col = QuizAttempt.completed_at

        sort_col = sort_col.desc() if order == 'desc' else sort_col.asc()
        base_query = query.order_by(sort_col)

        total = base_query.count()
        items = base_query.offset((page - 1) * per_page).limit(per_page).all()

        attempts_data = []
        for attempt in items:
            percentage = round((attempt.score / attempt.total_questions * 100) if attempt.total_questions > 0 else 0, 1)
            attempts_data.append({
                'id': attempt.id,
                'topic': attempt.topic,
                'score': attempt.score,
                'total_questions': attempt.total_questions,
                'percentage': percentage,
                'completed_at': attempt.completed_at.strftime('%Y-%m-%d %H:%M'),
                'grade': get_grade(percentage)
            })

        # If sorting by derived fields, sort in-memory
        if sort_by == 'percentage':
            attempts_data.sort(key=lambda a: a['percentage'], reverse=(order == 'desc'))
        if sort_by == 'grade':
            # Grade order A+, A, B, C, D, F
            grade_rank = {'A+': 6, 'A': 5, 'B': 4, 'C': 3, 'D': 2, 'F': 1}
            attempts_data.sort(key=lambda a: grade_rank.get(a['grade'], 0), reverse=(order == 'desc'))

        return jsonify({'success': True, 'attempts': attempts_data, 'page': page, 'per_page': per_page, 'total': total})
    except Exception as e:
        print(f"[v1][ERROR] Error in analytics_attempts: {e}"); return jsonify({'success': False, 'message': 'Could not load recent attempts.'}), 500

@app.route('/api/analytics/attempt/<int:attempt_id>')
@login_required
def analytics_attempt_detail(attempt_id):
    user_id = session['user_id']
    try:
        attempt = QuizAttempt.query.filter_by(id=attempt_id, user_id=user_id).first_or_404()
        answers = QuizAnswer.query.filter_by(attempt_id=attempt_id).order_by(QuizAnswer.id).all()
        answers_data = []
        for answer in answers:
            try:
                options = json.loads(answer.options_json) if answer.options_json else None
                correct_answer = json.loads(answer.correct_answer_json) if answer.correct_answer_json is not None else None
                user_answer = json.loads(answer.user_answer_json) if answer.user_answer_json is not None else None
            except (json.JSONDecodeError, TypeError): options, correct_answer, user_answer = "Error", "Error", "Error"

            answers_data.append({
                'question_text': answer.question_text, 'question_type': answer.question_type, 'options': options,
                'correct_answer': correct_answer, 'user_answer': user_answer, 'is_correct': answer.is_correct,
                'explanation': answer.explanation, 'time_spent': answer.time_spent_seconds
            })
        return jsonify({'success': True, 'attempt': {
            'id': attempt.id, 'topic': attempt.topic, 'score': attempt.score, 'total_questions': attempt.total_questions,
            'completed_at': attempt.completed_at.strftime('%Y-%m-%d %H:%M'), 'answers': answers_data
        }})
    except Exception as e:
        print(f"[v1][ERROR] Error in analytics_attempt_detail for ID {attempt_id}: {e}"); return jsonify({'success': False, 'message': 'Could not load attempt details.'}), 500

@app.route('/api/analytics/leaderboard')
@login_required
def analytics_leaderboard():
    user_id = session['user_id']
    try:
        attempts = QuizAttempt.query.filter_by(user_id=user_id).all()
        if not attempts: return jsonify({'success': True, 'leaderboard': []})
        user_scores = []
        for attempt in attempts:
            if attempt.total_questions > 0:
                score_percentage = (attempt.score / attempt.total_questions * 100)
                user_scores.append({
                    'topic': attempt.topic, 'score_percentage': round(score_percentage, 1),
                    'score': attempt.score, 'total_questions': attempt.total_questions,
                    'completed_at': attempt.completed_at.strftime('%Y-%m-%d %H:%M'), 'grade': get_grade(score_percentage)
                })
        user_scores.sort(key=lambda x: (x['score_percentage'], x['completed_at']), reverse=True)
        return jsonify({'success': True, 'leaderboard': user_scores[:5]}) # Top 5 personal
    except Exception as e:
        print(f"[v1][ERROR] Error in analytics_leaderboard: {e}"); return jsonify({'success': False, 'message': 'Could not load personal bests.'}), 500

@app.route('/api/analytics/charts')
@login_required
def analytics_charts():
    user_id = session['user_id']
    try:
        attempts = QuizAttempt.query.filter_by(user_id=user_id).order_by(QuizAttempt.completed_at.asc()).all()
        score_ranges = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
        subject_performance = {}
        progress_over_time = []
        if not attempts:
             return jsonify({'success': True, 'charts': {'score_distribution': score_ranges, 'subject_performance': {}, 'progress_over_time': []}})

        for attempt in attempts:
            if attempt.total_questions > 0:
                percentage = (attempt.score / attempt.total_questions * 100)
                if percentage <= 20: score_ranges['0-20'] += 1
                elif percentage <= 40: score_ranges['21-40'] += 1
                elif percentage <= 60: score_ranges['41-60'] += 1
                elif percentage <= 80: score_ranges['61-80'] += 1
                else: score_ranges['81-100'] += 1
                topic = attempt.topic
                if topic not in subject_performance: subject_performance[topic] = {'total': 0, 'correct': 0}
                subject_performance[topic]['total'] += attempt.total_questions
                subject_performance[topic]['correct'] += attempt.score
                progress_over_time.append({'date': attempt.completed_at.strftime('%Y-%m-%d'), 'score': round(percentage, 1)})
        subject_data = {topic: round((data['correct'] / data['total'] * 100) if data['total'] > 0 else 0, 1) for topic, data in subject_performance.items()}
        MAX_PROGRESS_POINTS = 15
        if len(progress_over_time) > MAX_PROGRESS_POINTS: progress_over_time = progress_over_time[-MAX_PROGRESS_POINTS:]
        return jsonify({'success': True, 'charts': {'score_distribution': score_ranges, 'subject_performance': subject_data, 'progress_over_time': progress_over_time}})
    except Exception as e:
        print(f"[v1][ERROR] Error in analytics_charts: {e}"); return jsonify({'success': False, 'message': 'Could not load chart data.'}), 500

@app.route('/api/quiz-attempt/<int:attempt_id>')
@login_required
def get_quiz_attempt_details(attempt_id):
    user_id = session['user_id']
    try:
        # Verify the attempt belongs to the current user
        attempt = QuizAttempt.query.filter_by(id=attempt_id, user_id=user_id).first()
        if not attempt:
            return jsonify({'success': False, 'message': 'Quiz attempt not found.'}), 404
        
        # Get all answers for this attempt
        answers = QuizAnswer.query.filter_by(attempt_id=attempt_id).order_by(QuizAnswer.id).all()
        questions_data = []
        
        for answer in answers:
            try:
                options = json.loads(answer.options_json) if answer.options_json else None
                correct_answer = json.loads(answer.correct_answer_json) if answer.correct_answer_json is not None else None
                user_answer = json.loads(answer.user_answer_json) if answer.user_answer_json is not None else None
            except (json.JSONDecodeError, TypeError): 
                options, correct_answer, user_answer = "Error", "Error", "Error"

            questions_data.append({
                'question_text': answer.question_text,
                'question_type': answer.question_type,
                'options': options,
                'correct_answer': correct_answer,
                'user_answer': user_answer,
                'is_correct': answer.is_correct,
                'explanation': answer.explanation,
                'time_spent': answer.time_spent_seconds
            })
        
        return jsonify({
            'success': True, 
            'attempt': {
                'id': attempt.id,
                'topic': attempt.topic,
                'score': attempt.score,
                'total_questions': attempt.total_questions,
                'percentage': round((attempt.score / attempt.total_questions) * 100, 1) if attempt.total_questions > 0 else 0,
                'completed_at': attempt.completed_at.strftime('%Y-%m-%d %H:%M'),
                'questions': questions_data
            }
        })
    except Exception as e: 
        print(f"[ERROR] Error getting quiz attempt details: {e}")
        return jsonify({'success': False, 'message': 'Could not load quiz attempt details.'}), 500

@app.route('/api/analytics/all-questions')
@login_required
def analytics_all_questions():
     user_id = session['user_id']
     try:
         all_answers = db.session.query(QuizAnswer, QuizAttempt).join(QuizAttempt, QuizAnswer.attempt_id == QuizAttempt.id).filter(QuizAttempt.user_id == user_id).order_by(QuizAttempt.completed_at.desc(), QuizAnswer.id.asc()).all()
         questions_data = []
         for answer, attempt in all_answers:
             try:
                 options = json.loads(answer.options_json) if answer.options_json else None
                 correct_answer = json.loads(answer.correct_answer_json) if answer.correct_answer_json is not None else None
                 user_answer = json.loads(answer.user_answer_json) if answer.user_answer_json is not None else None
             except (json.JSONDecodeError, TypeError): options, correct_answer, user_answer = "Parse Error", "Parse Error", "Parse Error"
             questions_data.append({
                 'attempt_id': attempt.id, 'topic': attempt.topic, 'completed_at': attempt.completed_at.strftime('%Y-%m-%d %H:%M'),
                 'question_text': answer.question_text, 'question_type': answer.question_type, 'options': options,
                 'correct_answer': correct_answer, 'user_answer': user_answer, 'is_correct': answer.is_correct,
                 'explanation': answer.explanation, 'time_spent': answer.time_spent_seconds
             })
         return jsonify({'success': True, 'total_questions': len(questions_data), 'questions': questions_data})
     except Exception as e:
        print(f"[v1][ERROR] Error in analytics_all_questions: {e}"); return jsonify({'success': False, 'message': 'Could not load all questions data.'}), 500

# --- AI Feedback Route ---
@app.route('/api/generate-feedback', methods=['POST'])
@login_required
def generate_ai_feedback():
    data = request.get_json(); topic = data.get('topic', 'General Knowledge'); score = data.get('score', 0); total_questions = data.get('total_questions', 1); incorrect_questions_text = data.get('incorrect_questions', [])
    if total_questions <= 0: return jsonify({'success': True, 'feedback': generate_basic_feedback(0, 1, topic)}) # Fallback
    try: score = int(score); total_questions = int(total_questions)
    except (ValueError, TypeError): return jsonify({'success': False, 'message': 'Score and total must be numbers.'}), 400

    try:
        groq_client = get_groq_client()
        percentage = round((score / total_questions) * 100) if total_questions > 0 else 0
        prompt = f"""Act as an encouraging educational tutor. A student completed a quiz on "{topic}".
Score: {score}/{total_questions} ({percentage}%)
Based *only* on the score and topic, provide concise, supportive feedback.
If available, consider these missed questions for context (limit 3): {json.dumps(incorrect_questions_text[:3]) if incorrect_questions_text else 'None provided'}
**Response Format:** Return **ONLY** valid JSON with these exact keys: "encouragement", "weak_areas", "study_tips", "motivation".
**Constraints:** Keep total feedback < 150 words. Be positive. Output *only* the JSON object."""

        response = groq_client.chat.completions.create(model="llama-3.1-8b-instant", messages=[{"role": "user", "content": prompt}], temperature=0.7, max_tokens=350)
        content = response.choices[0].message.content or ""; print(f"[v1][DEBUG] AI Feedback Raw: {content[:300]}...")
        feedback_data = None; json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            try:
                feedback_data = json.loads(json_match.group(0))
                if not all(k in feedback_data for k in ["encouragement", "weak_areas", "study_tips", "motivation"]):
                    print("[v1][WARN] AI Feedback JSON missing keys."); feedback_data = None
            except json.JSONDecodeError as json_err: print(f"[v1][ERROR] AI Feedback JSON parse failed: {json_err}."); feedback_data = None
        else: print("[v1][WARN] No JSON object in AI Feedback.")
        if feedback_data is None: print("[v1][INFO] Falling back to basic feedback."); feedback_data = generate_basic_feedback(score, total_questions, topic)
        return jsonify({'success': True, 'feedback': feedback_data})
    except ValueError as ve: print(f"[v1][ERROR] AI Feedback config error: {ve}"); return jsonify({'success': True, 'feedback': generate_basic_feedback(score, total_questions, topic)}) # Fallback
    except Exception as e: print(f"[v1][ERROR] Unexpected error generating AI feedback: {e}"); import traceback; traceback.print_exc(); return jsonify({'success': True, 'feedback': generate_basic_feedback(score, total_questions, topic)})

def generate_basic_feedback(score, total_questions, topic):
    percentage = round((score / total_questions) * 100) if total_questions > 0 else 0
    if percentage >= 90: return {"encouragement": f"Excellent work on {topic}! ({percentage}%)", "weak_areas": "Strong grasp!", "study_tips": "Explore advanced concepts.", "motivation": "Keep mastering! 🎉"}
    elif percentage >= 75: return {"encouragement": f"Great job on {topic}! ({percentage}%)", "weak_areas": "Review missed Qs.", "study_tips": "Focus on explanations.", "motivation": "Keep practicing! 💪"}
    elif percentage >= 50: return {"encouragement": f"Good effort on {topic}! ({percentage}%)", "weak_areas": "Review missed topics.", "study_tips": "Re-read material.", "motivation": "Making progress! 📚"}
    else: return {"encouragement": f"Thanks for trying {topic}!", "weak_areas": "Focus on fundamentals.", "study_tips": "Review explanations.", "motivation": "Keep learning! 🌟"}

def get_grade(percentage):
    if percentage >= 90: return 'A+'; 
    elif percentage >= 80: return 'A'; 
    elif percentage >= 70: return 'B'; 
    elif percentage >= 60: return 'C'; 
    elif percentage >= 50: return 'D'; 
    else: return 'F'

# --- Admin Authentication Routes ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if user and check_password_hash(user.password, data['password']) and user.is_admin:
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return jsonify({'success': True, 'message': 'Admin login successful'})

        return jsonify({'success': False, 'message': 'Invalid admin credentials or insufficient privileges'}), 401

    return render_template('admin-login.html')

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.get_json()
        
        # Check admin access code (set ADMIN_ACCESS_CODE in .env file for security)
        admin_access_code = os.getenv('ADMIN_ACCESS_CODE', 'admin2025')
        print(f"[ADMIN] Admin registration attempt with code: {data.get('admin_code', 'NOT_PROVIDED')}")
        if data.get('admin_code') != admin_access_code:
            return jsonify({'success': False, 'message': 'Invalid admin access code'}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        hashed_password = generate_password_hash(data['password'])
        
        new_user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            is_admin=True  # Grant admin privileges
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Admin registration successful'})

    return render_template('admin-register.html')

# --- [MODULE 6] Admin & Feedback Routes ---
@app.route('/api/submit-feedback', methods=['POST'])
@login_required
def submit_feedback():
    data = request.get_json(); question_text = data.get('question_text'); feedback_text = data.get('feedback_text'); is_flagged = data.get('is_flagged', False)
    if not question_text or not feedback_text or not feedback_text.strip(): return jsonify({'success': False, 'message': 'Missing question or feedback text.'}), 400
    try:
        feedback = QuestionFeedback(user_id=session['user_id'], question_text=str(question_text)[:10000], feedback_text=str(feedback_text).strip()[:2000], is_flagged=bool(is_flagged))
        db.session.add(feedback); db.session.commit()
        print(f"[v1][INFO] Feedback submitted by user {session['user_id']}")
        return jsonify({'success': True, 'message': 'Feedback submitted successfully. Thank you!'})
    except Exception as e: print(f"[v1][ERROR] Error saving feedback: {e}"); db.session.rollback(); return jsonify({'success': False, 'message': 'Could not save feedback due to a server error.'}), 500

@app.route('/admin')
@admin_required
def admin_dashboard():
    try:
        # Feedback data
        feedback_items = QuestionFeedback.query.filter_by(is_resolved=False).order_by(QuestionFeedback.is_flagged.desc(), QuestionFeedback.created_at.desc()).limit(100).all()
        flagged_count = QuestionFeedback.query.filter_by(is_flagged=True, is_resolved=False).count()
        
        # User statistics
        user_count = User.query.count()
        active_users = User.query.filter(User.created_at >= datetime.now() - timedelta(days=30)).count()
        recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
        
        # Quiz statistics
        quiz_count = QuizAttempt.query.count()
        total_quizzes = quiz_count
        avg_score = db.session.query(db.func.avg(QuizAttempt.score)).scalar() or 0
        avg_score = round(avg_score, 1)
        
        # Content statistics
        material_count = LearningMaterial.query.count()
        question_count = QuestionFeedback.query.count()  # Approximate question count
        recent_materials = LearningMaterial.query.order_by(LearningMaterial.created_at.desc()).limit(5).all()
        
        # Analytics data
        popular_subject = "General"  # Placeholder - could be calculated from actual data
        avg_duration = 15  # Placeholder - could be calculated from quiz attempts
        uptime = 99.9  # Placeholder - could be calculated from system logs
        
        return render_template('admin.html', 
            feedback_items=feedback_items,
            flagged_count=flagged_count,
            user_count=user_count,
            active_users=active_users,
            recent_users=recent_users,
            quiz_count=quiz_count,
            total_quizzes=total_quizzes,
            avg_score=avg_score,
            material_count=material_count,
            question_count=question_count,
            recent_materials=recent_materials,
            popular_subject=popular_subject,
            avg_duration=avg_duration,
            uptime=uptime
        )
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error loading admin dashboard: {e}")
        flash("Could not load admin data.", "danger")
        return redirect(url_for('index'))

@app.route('/admin/resolve-feedback/<int:feedback_id>', methods=['POST'])
@admin_required
def resolve_feedback(feedback_id):
    try:
        feedback = QuestionFeedback.query.get(feedback_id)
        if feedback: 
            feedback.is_resolved = True
            db.session.commit()
            return jsonify({'success': True, 'message': f'Feedback ID {feedback_id} marked as resolved.'})
        else: 
            return jsonify({'success': False, 'message': 'Feedback item not found.'}), 404
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error resolving feedback: {e}")
        return jsonify({'success': False, 'message': 'Error resolving feedback.'}), 500

@app.route('/admin/resolve-all-feedback', methods=['POST'])
@admin_required
def resolve_all_feedback():
    try:
        feedback_items = QuestionFeedback.query.filter_by(is_resolved=False).all()
        for feedback in feedback_items:
            feedback.is_resolved = True
        db.session.commit()
        return jsonify({'success': True, 'message': f'All {len(feedback_items)} feedback items marked as resolved.'})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error resolving all feedback: {e}")
        return jsonify({'success': False, 'message': 'Error resolving all feedback.'}), 500

@app.route('/admin/feedback-details/<int:feedback_id>')
@admin_required
def feedback_details(feedback_id):
    try:
        feedback = QuestionFeedback.query.get(feedback_id)
        if feedback:
            return jsonify({
                'question_text': feedback.question_text,
                'feedback_text': feedback.feedback_text,
                'user_id': feedback.user_id,
                'created_at': feedback.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_flagged': feedback.is_flagged
            })
        else:
            return jsonify({'error': 'Feedback not found'}), 404
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error getting feedback details: {e}")
        return jsonify({'error': 'Error retrieving feedback details'}), 500

@app.route('/admin/material-details/<int:material_id>')
@admin_required
def material_details(material_id):
    try:
        material = LearningMaterial.query.get(material_id)
        if material:
            return jsonify({
                'success': True,
                'material': {
                    'id': material.id,
                    'title': material.title,
                    'content': material.content,
                    'material_type': material.material_type,
                    'created_at': material.created_at.strftime('%Y-%m-%d %H:%M'),
                    'user_id': material.user_id
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Material not found.'}), 404
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error getting material details: {e}")
        return jsonify({'success': False, 'message': 'Error retrieving material details.'}), 500

@app.route('/admin/update-material/<int:material_id>', methods=['PUT'])
@admin_required
def update_material(material_id):
    try:
        material = LearningMaterial.query.get(material_id)
        if not material:
            return jsonify({'success': False, 'message': 'Material not found.'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided.'}), 400
        
        # Update material fields
        material.title = data.get('title', material.title)
        material.content = data.get('content', material.content)
        material.material_type = data.get('material_type', material.material_type)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Material updated successfully.'})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error updating material: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error updating material.'}), 500

@app.route('/admin/delete-material/<int:material_id>', methods=['DELETE'])
@admin_required
def delete_material(material_id):
    try:
        material = LearningMaterial.query.get(material_id)
        if material:
            db.session.delete(material)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Material deleted successfully.'})
        else:
            return jsonify({'success': False, 'message': 'Material not found.'}), 404
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error deleting material: {e}")
        return jsonify({'success': False, 'message': 'Error deleting material.'}), 500

@app.route('/admin/export-users')
@admin_required
def export_users():
    try:
        users = User.query.all()
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'created_at': user.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_admin': user.is_admin
            })
        return jsonify({'success': True, 'data': user_data})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error exporting users: {e}")
        return jsonify({'success': False, 'message': 'Error exporting users.'}), 500

@app.route('/admin/export-analytics')
@admin_required
def export_analytics():
    try:
        analytics_data = {
            'total_users': User.query.count(),
            'total_quizzes': QuizAttempt.query.count(),
            'total_materials': LearningMaterial.query.count(),
            'total_feedback': QuestionFeedback.query.count(),
            'flagged_feedback': QuestionFeedback.query.filter_by(is_flagged=True).count(),
            'resolved_feedback': QuestionFeedback.query.filter_by(is_resolved=True).count(),
            'avg_score': round(db.session.query(db.func.avg(QuizAttempt.score)).scalar() or 0, 1)
        }
        return jsonify({'success': True, 'data': analytics_data})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error exporting analytics: {e}")
        return jsonify({'success': False, 'message': 'Error exporting analytics.'}), 500

# --- Enhanced Feedback Management Routes ---
@app.route('/admin/feedback-list')
@admin_required
def feedback_list():
    try:
        feedback_items = QuestionFeedback.query.filter_by(is_resolved=False).order_by(QuestionFeedback.created_at.desc()).all()
        feedback_data = []
        for item in feedback_items:
            feedback_data.append({
                'id': item.id,
                'user_id': item.user_id,
                'question_text': item.question_text,
                'feedback_text': item.feedback_text,
                'is_flagged': item.is_flagged,
                'created_at': item.created_at.strftime('%Y-%m-%d %H:%M')
            })
        return jsonify({'success': True, 'feedback_items': feedback_data})
    except Exception as e:
        print(f"[ADMIN][ERROR] Error fetching feedback list: {e}")
        return jsonify({'success': False, 'message': 'Error fetching feedback list.'}), 500

@app.route('/admin/flag-feedback/<int:feedback_id>', methods=['POST'])
@admin_required
def flag_feedback(feedback_id):
    try:
        feedback = QuestionFeedback.query.get(feedback_id)
        if feedback:
            feedback.is_flagged = True
            db.session.commit()
            return jsonify({'success': True, 'message': 'Feedback flagged successfully.'})
        else:
            return jsonify({'success': False, 'message': 'Feedback not found.'}), 404
    except Exception as e:
        print(f"[ADMIN][ERROR] Error flagging feedback: {e}")
        return jsonify({'success': False, 'message': 'Error flagging feedback.'}), 500

@app.route('/admin/unflag-feedback/<int:feedback_id>', methods=['POST'])
@admin_required
def unflag_feedback(feedback_id):
    try:
        feedback = QuestionFeedback.query.get(feedback_id)
        if feedback:
            feedback.is_flagged = False
            db.session.commit()
            return jsonify({'success': True, 'message': 'Flag removed successfully.'})
        else:
            return jsonify({'success': False, 'message': 'Feedback not found.'}), 404
    except Exception as e:
        print(f"[ADMIN][ERROR] Error removing flag: {e}")
        return jsonify({'success': False, 'message': 'Error removing flag.'}), 500

# Test route to create sample flagged feedback
@app.route('/admin/create-test-flagged-feedback', methods=['POST'])
@admin_required
def create_test_flagged_feedback():
    try:
        # Create some test flagged feedback
        test_feedback = [
            QuestionFeedback(
                user_id=1,
                question_text="This is a test flagged question with inappropriate content",
                feedback_text="This question contains offensive language and should be removed immediately.",
                is_flagged=True,
                is_resolved=False,
                created_at=datetime.now()
            ),
            QuestionFeedback(
                user_id=2,
                question_text="Another flagged question with spam content",
                feedback_text="This appears to be spam and should be flagged for review.",
                is_flagged=True,
                is_resolved=False,
                created_at=datetime.now() - timedelta(hours=2)
            ),
            QuestionFeedback(
                user_id=3,
                question_text="Normal question without issues",
                feedback_text="This is regular feedback that should not be flagged.",
                is_flagged=False,
                is_resolved=False,
                created_at=datetime.now() - timedelta(hours=1)
            )
        ]
        
        for feedback in test_feedback:
            db.session.add(feedback)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Test flagged feedback created successfully.'})
    except Exception as e:
        print(f"[ADMIN][ERROR] Error creating test feedback: {e}")
        return jsonify({'success': False, 'message': 'Error creating test feedback.'}), 500

# Debug route to check feedback status
@app.route('/admin/debug-feedback')
@admin_required
def debug_feedback():
    try:
        all_feedback = QuestionFeedback.query.all()
        flagged_feedback = QuestionFeedback.query.filter_by(is_flagged=True).all()
        unresolved_feedback = QuestionFeedback.query.filter_by(is_resolved=False).all()
        
        debug_info = {
            'total_feedback': len(all_feedback),
            'flagged_feedback': len(flagged_feedback),
            'unresolved_feedback': len(unresolved_feedback),
            'flagged_items': [
                {
                    'id': item.id,
                    'user_id': item.user_id,
                    'question_text': item.question_text[:50] + '...',
                    'feedback_text': item.feedback_text[:50] + '...',
                    'is_flagged': item.is_flagged,
                    'is_resolved': item.is_resolved,
                    'created_at': item.created_at.strftime('%Y-%m-%d %H:%M')
                }
                for item in flagged_feedback
            ]
        }
        
        return jsonify({'success': True, 'debug_info': debug_info})
    except Exception as e:
        print(f"[ADMIN][ERROR] Error in debug feedback: {e}")
        return jsonify({'success': False, 'message': 'Error in debug feedback.'}), 500

# --- User Management Routes ---
@app.route('/admin/user-details/<int:user_id>')
@admin_required
def user_details(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            # Get user statistics
            total_quizzes = QuizAttempt.query.filter_by(user_id=user_id).count()
            total_materials = LearningMaterial.query.filter_by(user_id=user_id).count()
            total_feedback = QuestionFeedback.query.filter_by(user_id=user_id).count()
            
            # Calculate average score
            avg_score = 0
            if total_quizzes > 0:
                quiz_scores = db.session.query(QuizAttempt.score, QuizAttempt.total_questions).filter_by(user_id=user_id).all()
                if quiz_scores:
                    total_percentage = sum((score / total) * 100 for score, total in quiz_scores if total > 0)
                    avg_score = round(total_percentage / len(quiz_scores), 1)
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'created_at': user.created_at.strftime('%Y-%m-%d %H:%M'),
                    'total_quizzes': total_quizzes,
                    'total_materials': total_materials,
                    'total_feedback': total_feedback,
                    'avg_score': avg_score
                }
            })
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error getting user details: {e}")
        return jsonify({'success': False, 'message': 'Error retrieving user details.'}), 500

@app.route('/admin/update-user/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided.'}), 400
        
        # Check if username or email already exists (excluding current user)
        if 'username' in data and data['username'] != user.username:
            existing_user = User.query.filter(User.username == data['username'], User.id != user_id).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Username already exists.'}), 400
        
        if 'email' in data and data['email'] != user.email:
            existing_user = User.query.filter(User.email == data['email'], User.id != user_id).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Email already exists.'}), 400
        
        # Update user fields
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'is_admin' in data:
            user.is_admin = bool(data['is_admin'])
        if 'password' in data and data['password'].strip():
            user.password = generate_password_hash(data['password'])
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully.'})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error updating user: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error updating user.'}), 500

@app.route('/admin/user-statistics')
@admin_required
def user_statistics():
    try:
        # Overall statistics
        total_users = User.query.count()
        admin_users = User.query.filter_by(is_admin=True).count()
        total_quizzes = QuizAttempt.query.count()
        
        # Calculate average score across all users
        avg_score = 0
        if total_quizzes > 0:
            quiz_scores = db.session.query(QuizAttempt.score, QuizAttempt.total_questions).all()
            if quiz_scores:
                total_percentage = sum((score / total) * 100 for score, total in quiz_scores if total > 0)
                avg_score = round(total_percentage / len(quiz_scores), 1)
        
        # Recent users
        recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
        recent_users_data = [{
            'username': user.username,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M')
        } for user in recent_users]
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'admin_users': admin_users,
                'total_quizzes': total_quizzes,
                'avg_score': avg_score,
                'recent_users': recent_users_data
            }
        })
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error getting user statistics: {e}")
        return jsonify({'success': False, 'message': 'Error retrieving user statistics.'}), 500

@app.route('/admin/user-statistics/<int:user_id>')
@admin_required
def user_statistics_single(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
        
        # Get user-specific statistics
        total_quizzes = QuizAttempt.query.filter_by(user_id=user_id).count()
        total_materials = LearningMaterial.query.filter_by(user_id=user_id).count()
        total_feedback = QuestionFeedback.query.filter_by(user_id=user_id).count()
        
        # Calculate average score
        avg_score = 0
        if total_quizzes > 0:
            quiz_scores = db.session.query(QuizAttempt.score, QuizAttempt.total_questions).filter_by(user_id=user_id).all()
            if quiz_scores:
                total_percentage = sum((score / total) * 100 for score, total in quiz_scores if total > 0)
                avg_score = round(total_percentage / len(quiz_scores), 1)
        
        return jsonify({
            'success': True,
            'stats': {
                'total_quizzes': total_quizzes,
                'total_materials': total_materials,
                'total_feedback': total_feedback,
                'avg_score': avg_score
            }
        })
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error getting user statistics: {e}")
        return jsonify({'success': False, 'message': 'Error retrieving user statistics.'}), 500

@app.route('/admin/export-user-statistics')
@admin_required
def export_user_statistics():
    try:
        # Get overall statistics
        total_users = User.query.count()
        admin_users = User.query.filter_by(is_admin=True).count()
        total_quizzes = QuizAttempt.query.count()
        
        # Calculate average score
        avg_score = 0
        if total_quizzes > 0:
            quiz_scores = db.session.query(QuizAttempt.score, QuizAttempt.total_questions).all()
            if quiz_scores:
                total_percentage = sum((score / total) * 100 for score, total in quiz_scores if total > 0)
                avg_score = round(total_percentage / len(quiz_scores), 1)
        
        stats_data = {
            'total_users': total_users,
            'admin_users': admin_users,
            'total_quizzes': total_quizzes,
            'avg_score': avg_score
        }
        
        return jsonify({'success': True, 'stats': stats_data})
    except Exception as e: 
        print(f"[ADMIN][ERROR] Error exporting user statistics: {e}")
        return jsonify({'success': False, 'message': 'Error exporting user statistics.'}), 500

# --- Demo Route ---
@app.route('/api/demo-evaluate')
def demo_evaluate():
    """Useful non-auth route for testing evaluation logic."""
    examples = []
    q1 = {'question': 'Cap France?', 'question_type': 'mcq_single', 'options': ['Berlin', 'Paris', 'Rome', 'Madrid'], 'correct_answer': 1, 'explanation': '...'}
    examples.append({'case': 'MCQ1 OK', 'q': q1, 'ans': 1}); examples.append({'case': 'MCQ1 WRONG', 'q': q1, 'ans': 0})
    q2 = {'question': 'Primes?', 'question_type': 'mcq_multiple', 'options': ['4', '5', '6', '7'], 'correct_answer': [1, 3], 'explanation': '...'}
    examples.append({'case': 'MCQM OK', 'q': q2, 'ans': [1, 3]}); examples.append({'case': 'MCQM PART', 'q': q2, 'ans': [1]}); examples.append({'case': 'MCQM WRONG', 'q': q2, 'ans': [0, 2]})
    q3 = {'question': 'Flat earth?', 'question_type': 'true_false', 'correct_answer': False, 'explanation': '...'}
    examples.append({'case': 'TF OK', 'q': q3, 'ans': 'false'}); examples.append({'case': 'TF WRONG', 'q': q3, 'ans': True})
    q4 = {'question': 'Plant food?', 'question_type': 'short_answer', 'correct_answer': 'Photosynthesis', 'explanation': '...'}
    examples.append({'case': 'SA OK', 'q': q4, 'ans': 'Photosynthesis'}); examples.append({'case': 'SA VAR', 'q': q4, 'ans': ' photosynthesis. '}); examples.append({'case': 'SA WRONG', 'q': q4, 'ans': 'Respiration'})
    results = []
    for ex in examples: ev = evaluate_answer(ex['q'], ex['ans']); fb = generate_feedback(ex['q'], ev); results.append({'case': ex['case'], 'eval': ev, 'fb': fb})
    return jsonify({'success': True, 'demo_results': results})


@app.route('/contact')
def contact():
    """Contact page with full contact information"""
    return render_template('contact.html')

if __name__ == '__main__':
    # Set debug=False for production
    # Use host='0.0.0.0' to make accessible on your local network
    app.run(debug=True, host='0.0.0.0', port=5000)