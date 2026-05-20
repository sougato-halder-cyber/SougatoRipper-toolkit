# 🔒 Automated Security & Monitoring Toolkit

A comprehensive, GUI-based desktop application for automated reconnaissance, vulnerability testing, file encryption, and system monitoring — built with Python & Tkinter.

## 📋 Features

| Module | Features |
|--------|----------|
| **Reconnaissance** | Subdomain Enumeration, Port Scanning |
| **Vulnerability Testing** | SQL Injection Tester, Password Strength Checker, Brute Force Simulator |
| **Data Protection** | File Encryptor/Decryptor (Fernet), Secure Password Generator |
| **System Monitoring** | Activity Logger, Screenshot Capture |
| **Reporting** | Automated Excel Report Generation |

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/SougatoRipper/security-toolkit.git
cd security-toolkit

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## ▶️ Usage

### Run from Source
```bash
python app.py
```

### Build Executable (.exe)
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name SecurityToolkit app.py
```
The `.exe` will be in the `dist/` folder.

## 📁 Project Structure

```
.
├── app.py                 # Main Tkinter GUI
├── scanner.py             # Reconnaissance & Network Scanner
├── sqli_tester.py         # SQL Injection & Password Testing
├── crypto_tool.py         # File Encryption & Password Generation
├── monitor.py             # System Monitoring & Screenshots
├── reporter.py            # Excel Report Generation
├── requirements.txt       # Python dependencies
├── README.md              # Project documentation
└── data/
    ├── wordlists/         # Subdomain & password wordlists
    ├── screenshots/       # Captured screenshots
    ├── reports/           # Generated Excel reports
    └── crypto/            # Encryption keys & hashes
```

## ⚠️ Disclaimer

**This tool is for educational and authorized testing purposes only.**
Do not use on systems you do not own or have explicit permission to test.
The authors are not responsible for any misuse or damage caused by this tool.

## 👨‍💻 Author

**SougatoRipper**

---
*Built as the Final Project for Python Online Batch.*
