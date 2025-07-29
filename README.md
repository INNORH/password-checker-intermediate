# Password Strength Checker (Intermediate Level)

A more advanced Python tool and web app for checking password strength. This version includes:
- Entropy calculation
- Common password blacklist
- Password breach check (using HaveIBeenPwned API)
- Enhanced feedback and suggestions

## Features
- Checks password length, character variety, and entropy
- Checks against a blacklist of common passwords
- Checks if the password has been exposed in data breaches (optional, requires internet)
- Provides actionable feedback

## Usage

### CLI
Run the following command in your terminal:

```
python password_checker.py
```

### Web App
Run the following command:

```
python app.py
```

Then open your browser at http://127.0.0.1:5000

## Requirements
- Python 3.7+
- Flask
- requests

Install dependencies:

```
pip install -r requirements.txt
```
