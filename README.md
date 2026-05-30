# SougatoCracker

SougatoCracker is a GUI-based Python final project: an **Automated Security & Monitoring Toolkit** built with Tkinter and OOP principles.

> Ethical use only: run reconnaissance and testing only on systems you own or where you have written permission.

## Features

### 1. Reconnaissance & Network Scanner
- Subdomain enumerator using a local wordlist and `requests`
- TCP port scanner for common ports and service names

### 2. Vulnerability Testing
- Basic SQL injection error-based tester for authorized URLs with parameters
- SHA-256 password hashing
- Local dictionary-based brute-force simulator for learning hash cracking concepts

### 3. Data Protection
- Fernet symmetric file encryption and decryption
- Secure password generator with salted SHA-256 hash output

### 4. System Monitoring & Reporting
- Visible, consent-based screenshot saver and activity logger
- Excel report generation using `openpyxl`

## Project Structure

```text
SougatoCracker/
├── app.py
├── requirements.txt
├── build_exe.bat
├── SougatoCracker.spec
├── core/
│   ├── scanner.py
│   ├── vulnerability.py
│   ├── crypto_tool.py
│   ├── monitor.py
│   └── utils.py
└── data/
    ├── wordlists/
    ├── screenshots/
    ├── reports/
    └── keys/
```

## Installation

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Run the GUI

```bash
python app.py
```

## Build Windows EXE

On Windows, run:

```bat
build_exe.bat
```

Or manually:

```bash
pip install -r requirements.txt
pyinstaller --noconfirm --onefile --windowed --name SougatoCracker app.py
```

The EXE will be created here:

```text
dist/SougatoCracker.exe
```

## Upload to GitHub

Create a new GitHub repository named `SougatoCracker`, then run these commands from inside the project folder:

```bash
git init
git add .
git commit -m "Initial commit: SougatoCracker final project"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/SougatoCracker.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username.

## 15-Minute Presentation Flow

1. Show the Tkinter dashboard and explain the OOP structure.
2. Run a localhost or authorized target port scan.
3. Run subdomain enumeration on an authorized domain.
4. Demonstrate SQLi tester on a legal test site or local vulnerable lab only.
5. Hash a password and run the local dictionary simulator.
6. Encrypt and decrypt a sample text file.
7. Generate a strong password and explain salted hashing.
8. Capture a consent-based screenshot and show activity logging.
9. Generate the Excel report.
10. Explain ethical limitations and authorization checkbox.

## Notes for Review

- The project uses classes, encapsulation, separate logic modules, and a GUI dashboard.
- Network and vulnerability modules include an authorization checkbox to support ethical testing.
- Monitoring is not hidden; it requires visible user action.


## Teacher Review Fixes Included

- Port Scanner supports continuous ranges like `1-100` as well as comma-separated ports like `22,80,443`.
- Password Strength button now shows only Weak/Medium/Strong plus advice; it does not display the hash.
- File decrypt restores the original filename when decrypting a `.encrypted` file, and creates `.decrypted` only if the original file already exists.
- Report generation uses live scan/test results only. It does not insert demo/fake rows.
- Log file is visible from the Monitoring tab and Report tab via the Show Log File button.
