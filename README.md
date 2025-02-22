# README

## Flask Malware Scanner and Ransomware Chatbot Application

This project is a web application built using Flask. It serves two main purposes:

1. **Malware Scanner**: Scans uploaded files and folders for known malware signatures and suspicious patterns.
2. **Chatbot**: Provides assistance with ransomware-related queries using Google's Generative AI.

---

## Features

### **1. User Authentication**
- **Login and Signup**: Allows users to create accounts and log in securely.
- **Session Management**: Ensures that only logged-in users can access certain functionalities.

### **2. Malware Scanning**
- **File Upload and Scan**: Upload files to be scanned for malware or suspicious patterns.
- **Folder Scanning**: Recursively scan an entire folder and display detailed results.
- **Real-time External Drive Monitoring**: Detect and monitor newly connected drives for potential threats.

### **3. Ransomware Chatbot**
- **Chat Interface**: Users can ask questions about ransomware-related topics.
- **Keyword Filtering**: Ensures the chatbot responds only to ransomware-specific queries.
- **Powered by Google's Generative AI**: Configured to provide informative and accurate responses.

### **4. Malware Detection**
- **Signature Matching**: Compares file hashes with known malware signatures.
- **Pattern Matching**: Scans for suspicious binary or text patterns such as NOP sleds or the EICAR test string.

### **5. User-Friendly Interface**
- HTML templates for login, signup, scanning results, and chatbot interaction.

---

## Getting Started

### Prerequisites
- Python 3.8+
- Flask
- psutil
- Google Generative AI Python SDK
- Basic knowledge of Flask for deployment and configuration

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your_username/repo_name.git
   ```
2. Navigate to the project directory:
   ```bash
   cd repo_name
   ```
3. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up the required directories:
   ```bash
   mkdir uploads
   mkdir ransome_errors
   ```

### Configuration
1. Set the secret key in the `app.secret_key` variable.
2. Add your Google Generative AI API key to the `genai.configure(api_key="YOUR_API_KEY")` line.

### Running the Application
1. Start the Flask development server:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## API Endpoints

### **Authentication**
- `/login` - User login page
- `/signup` - User signup page
- `/logout` - Logs out the current user

### **Malware Scanning**
- `/scan` - Upload and scan a file
- `/scan_folder` - Scan an entire folder
- `/get_drives` - Get the list of currently connected drives

### **Ransomware Chatbot**
- `/chatbot` - Interface for ransomware-related queries

---

## File Structure
```
project_directory/
│
├── app.py                  # Main application file
├── templates/              # HTML templates for the web interface
│   ├── login.html
│   ├── signup.html
│   ├── index.html
│   ├── frontpage.html
│   ├── result.html
│   ├── folder_scan_results.html
│   └── chatbot.html
├── uploads/                # Directory for uploaded files
├── ransome_errors/         # Directory for errors or quarantined files
└── requirements.txt        # List of required Python packages
```

---

## Security Notes
- Replace the default `app.secret_key` with a strong, unique key.
- Use HTTPS in production to encrypt data in transit.
- Avoid storing sensitive information like passwords or API keys in plaintext.

---

## Future Improvements
- **Database Integration**: Replace the in-memory user database with a persistent database like SQLite or PostgreSQL.
- **Enhanced Malware Detection**: Include heuristic and behavioral analysis.
- **Chatbot Optimization**: Improve context retention for better interaction.
- **UI Enhancements**: Use a modern frontend framework for improved aesthetics.

---

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
