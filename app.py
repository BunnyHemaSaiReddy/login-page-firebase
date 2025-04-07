from flask import Flask, render_template, request, redirect, session, flash, url_for
import pyrebase
from firebase_config import firebase_config
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Use a secure key in production

firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()

# ========== ROUTES ==========

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signin-option')
def signin_option():
    return render_template('signin.html')

# -------- Signup --------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth.create_user_with_email_and_password(email, password)
            auth.send_email_verification(user['idToken'])
            flash("Verification email sent! Please check your inbox.")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Signup failed: {e}")
            return redirect(url_for('signup'))
    return render_template('signup.html')

# -------- Login --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            user_info = auth.get_account_info(user['idToken'])
            verified = user_info['users'][0]['emailVerified']
            if not verified:
                flash("Please verify your email before logging in.")
                return redirect(url_for('login'))
            session['user'] = email
            return redirect(url_for('index'))
        except requests.exceptions.HTTPError as e:
            error_json = e.response.json()
            error_message = error_json['error']['message']
            if error_message == 'EMAIL_NOT_FOUND':
                flash("Email not found. Please sign up.")
                return redirect(url_for('signup'))
            elif error_message == 'INVALID_PASSWORD':
                flash("Invalid password.")
                return redirect(url_for('login'))
            else:
                flash("Login failed.")
                return redirect(url_for('login'))
    return render_template('login.html')

# -------- Forgot Password --------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            auth.send_password_reset_email(email)
            flash('Password reset link sent to your email.')
        except:
            flash('Error sending reset email. Try again.')
        return redirect(url_for('login'))
    return render_template('forgot-password.html')

# -------- Google Login (using Firebase Web SDK, token from frontend) --------
@app.route('/google-login', methods=['POST'])
def google_login():
    id_token = request.json.get('idToken')
    try:
        req_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={firebase_config['apiKey']}"
        headers = {'Content-Type': 'application/json'}
        res = requests.post(req_url, json={'idToken': id_token}, headers=headers)
        user_info = res.json()
        email = user_info['users'][0]['email']
        session['user'] = email
        return redirect(url_for('index'))
    except Exception as e:
        return {"error": str(e)}, 400

# -------- Index (Dashboard) --------
@app.route('/index')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user=session['user'])

# -------- Logout --------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# ========== RUN ==========

if __name__ == '__main__':
    app.run(debug=True)
