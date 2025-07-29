import re
import math
import requests

# Load a blacklist of common passwords
with open('common_passwords.txt', 'r', encoding='utf-8') as f:
    COMMON_PASSWORDS = set(line.strip() for line in f)

HIBP_API = 'https://api.pwnedpasswords.com/range/'

def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'\d', password):
        charset += 10
    if re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def check_pwned(password):
    import hashlib
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(HIBP_API + prefix, timeout=5)
        if res.status_code == 200:
            hashes = (line.split(':') for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
    except Exception:
        pass
    return 0

def check_password_strength(password, check_breach=True):
    feedback = []
    score = 0
    entropy = calculate_entropy(password)

    # Length check
    if len(password) < 12:
        feedback.append("Password should be at least 12 characters long.")
    else:
        score += 1

    # Character variety
    if not re.search(r'[A-Z]', password):
        feedback.append("Add at least one uppercase letter.")
    else:
        score += 1
    if not re.search(r'[a-z]', password):
        feedback.append("Add at least one lowercase letter.")
    else:
        score += 1
    if not re.search(r'\d', password):
        feedback.append("Add at least one digit.")
    else:
        score += 1
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        feedback.append("Add at least one special character.")
    else:
        score += 1

    # Entropy check
    if entropy < 50:
        feedback.append(f"Increase password complexity. Entropy: {entropy} bits (recommended: 50+ bits).")
    else:
        score += 1

    # Blacklist check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("This password is too common. Choose something more unique.")
    else:
        score += 1

    # Breach check
    pwned_count = 0
    if check_breach:
        pwned_count = check_pwned(password)
        if pwned_count > 0:
            feedback.append(f"This password has appeared in {pwned_count} data breaches! Do not use it.")
        else:
            score += 1

    if score >= 7:
        feedback.append("Excellent password!")
    elif score >= 5:
        feedback.append("Good password, but could be improved.")
    else:
        feedback.append("Weak password. Please improve it.")

    return score, feedback, entropy, pwned_count

def main():
    password = input("Enter your password: ")
    score, feedback, entropy, pwned_count = check_password_strength(password)
    print(f"\nPassword Strength Score: {score} / 8")
    print(f"Entropy: {entropy} bits")
    if pwned_count:
        print(f"Breached: Yes ({pwned_count} times)")
    else:
        print("Breached: No")
    print("Feedback:")
    for f in feedback:
        print("-", f)

if __name__ == "__main__":
    main()
