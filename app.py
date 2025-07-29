from flask import Flask, render_template, request
import password_checker

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    score = None
    feedback = []
    entropy = None
    pwned_count = None
    password = ''
    if request.method == 'POST':
        password = request.form['password']
        score, feedback, entropy, pwned_count = password_checker.check_password_strength(password)
    return render_template('index.html', score=score, feedback=feedback, entropy=entropy, pwned_count=pwned_count, password=password)

if __name__ == '__main__':
    app.run(debug=True)
