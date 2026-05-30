@echo off
REM Windows EXE builder for SougatoCracker
python -m venv .venv
call .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
pyinstaller --noconfirm --onefile --windowed --name SougatoCracker app.py
pause
