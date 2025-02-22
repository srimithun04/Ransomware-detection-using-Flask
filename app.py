from flask import Flask, request, render_template, jsonify, redirect, url_for, session
import os
import re
import hashlib
import google.generativeai as genai
import psutil
import threading
import time
from pathlib import Path
from threading import Thread

# Configure Google Generative AI with the API key
genai.configure(api_key="AIzaSyAxUIk4jV44TCnl67ifN1NGLUF7adlJR5o")

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set your own secret key
UPLOAD_FOLDER = 'uploads'
RECYCLE_BIN = 'ransome_errors'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RECYCLE_BIN, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Mock user database (replace with an actual database in production)
users_db = {}

# Define known malware signatures (MD5 hashes for example)
MALWARE_SIGNATURES = [
    "44d88612fea8a8f36de82e1278abb02f",  # Example MD5 hash
]

# Define suspicious patterns (NOP sled, breakpoint, EICAR test file pattern)
SUSPICIOUS_PATTERNS = [
    re.compile(rb'\x90{4,}'),  # NOP sled pattern
    re.compile(rb'\xCC{4,}'),  # Breakpoint pattern
    re.compile(rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")  # EICAR string
]


class MalwareDetector:

    def __init__(self):
        pass

    def get_file_hash(self, file_path):
            """Get the hash of a file (MD5)."""
            hash_md5 = hashlib.md5()
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
            except Exception as e:
                print(f"Error calculating hash: {e}")
            return hash_md5.hexdigest()

    # Function to monitor external drives
    def monitor_external_drives():
        previous_drives = set(part.device for part in psutil.disk_partitions(all=True))
        while True:
            current_drives = set(part.device for part in psutil.disk_partitions(all=True))
            new_drives = current_drives - previous_drives

            if new_drives:
                for drive in new_drives:
                    # Directly show the new drive without storing it
                    print(f"New external drive detected: {drive}")  # Debugging statement

            previous_drives = current_drives
            time.sleep(1)  # Reduce the interval for faster detection

    # Start the monitor function in a separate thread
    monitor_thread = Thread(target=monitor_external_drives, daemon=True)
    monitor_thread.start()

    def scan_file(self, file_path):
        """Scan a file for malware or suspicious content."""
        try:
            # Check file hash against known malware signatures
            file_hash = self.get_file_hash(file_path)
            if file_hash in MALWARE_SIGNATURES:
                return "Malware detected: Known signature match."

            # Read file content as binary
            with open(file_path, 'rb') as file:
                content = file.read()

            # Binary scan for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(content):
                    return "Suspicious patterns detected (binary)."

            # Text-based scan for other files
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                text_content = content.decode('latin-1', errors='ignore')

            # Check for suspicious text strings (e.g., EICAR test string)
            if "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in text_content:
                return "Suspicious patterns detected (text)."

            return "File is clean."
        except Exception as e:
            return f"Error scanning file: {e}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error message
    if request.method == 'POST':
        username = request.form['username']

        if username in users_db and users_db[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = "Invalid credentials. Please sign up if you don't have an account."

    return render_template('login.html', error=error)

@app.route('/get_drives', methods=['GET'])
def get_drives():
    current_drives = set(part.device for part in psutil.disk_partitions(all=True))
    return jsonify({"drives": list(current_drives)})
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users_db:
            error_message = "Username already exists!"
        else:
            users_db[username] = password
            return redirect(url_for('login'))

    return render_template('signup.html', error_message=error_message)


@app.route('/',methods=['GET','POST'])
def frontpage():
    return render_template('frontpage.html')

@app.route('/index')
def index():
    if 'username' not in session:
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    detector = MalwareDetector()
    result = detector.scan_file(file_path)

    return redirect(url_for('scan_result', result=result, file_path=file_path))


@app.route('/scan_result')
def scan_result():
    result = request.args.get('result')
    file_path = request.args.get('file_path')

    return render_template('result.html', result=result, file_path=file_path)


@app.route('/scan_folder', methods=['POST'])
def scan_folder():
    if 'username' not in session:
        return redirect(url_for('login'))

    folder_path = request.form.get('folder_path')
    if not folder_path or not os.path.isdir(folder_path):
        return jsonify({"error": "Invalid folder path."}), 400

    detector = MalwareDetector()
    scan_results = []

    # Extract only the folder name
    folder_name = os.path.basename(os.path.normpath(folder_path))

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            # Get the result of scanning
            file_path = os.path.join(root, file_name)
            result = detector.scan_file(file_path)
            # Add the result, including the folder name and file name only
            scan_results.append({"folder": folder_name, "file": file_name, "result": result})

    # Redirect to a results page with the scan results
    return render_template('folder_scan_results.html', results=scan_results)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/chatbot', methods=['GET', 'POST'])
def chatbot():
    if 'username' not in session:
        return redirect(url_for('login'))

    response_message = ""

    if request.method == 'POST':
        user_question = request.form['question']

        # Define allowed keywords strictly related to ransomware
        ALLOWED_KEYWORDS = [
            "ransomware", "encryption", "decrypt", "malware", "cyber attack",
            "data recovery", "ransom demand", "cybersecurity", "virus", "threats"
        ]

        # Split the question into sentences
        sentences = re.split(r'[.!?]', user_question)

        # Check if every sentence is ransomware-related
        for sentence in sentences:
            if sentence.strip() and not any(keyword.lower() in sentence.lower() for keyword in ALLOWED_KEYWORDS):
                response_message = (
                    "Sorry, I can only assist with questions specifically related to ransomware. "
                    "Please ask about ransomware, malware, encryption, or related topics."
                )
                return render_template('chatbot.html', response=response_message)

        try:
            # Configure the model for natural conversation
            generation_config = {
                "temperature": 0.7,  # Lower value for more focused responses
                "top_p": 0.9,
                "top_k": 50,
                "max_output_tokens": 500,  # Shorter output for natural chat
                "response_mime_type": "text/plain",
            }

            model = genai.GenerativeModel(
                model_name="gemini-2.0-flash",  # Ensure you're using the correct model
                generation_config=generation_config,
            )

            # Start the chat session
            chat_session = model.start_chat(history=[])

            # Send the user message to the model
            response = chat_session.send_message(user_question)

            # Get the response text and clean formatting
            response_message = response.text.strip()  # Remove extra spaces/newlines
            response_message = response_message.replace('**', '')  # Remove asterisks used for formatting

        except Exception as e:
            response_message = f"Oops! Something went wrong: {e}"

    return render_template('chatbot.html', response=response_message)


if __name__ == '__main__':
    app.run(debug=True)
