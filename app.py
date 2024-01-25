from flask import Flask, render_template, request, redirect, session, flash
from flask_mail import Mail, Message
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret"

# Configure MySQL
app.config['mysql_host'] = '127.0.0.1'
app.config['mysql_user'] = 'root'
app.config['mysql_password'] = 'root'
app.config['mysql_db'] = 'rajaqua'

app.config['SERVER_NAME'] = 'localhost:5000'

# Add the missing key to the app.config
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Remove 'unwanted_keywords' from app.config if present
unwanted_keywords = ['DEBUG', 'TESTING', 'PROPAGATE_EXCEPTIONS', 'SECRET_KEY', 'PERMANENT_SESSION_LIFETIME', 'USE_X_SENDFILE', 'SERVER_NAME', 'APPLICATION_ROOT', 'SESSION_COOKIE_NAME', 'SESSION_COOKIE_DOMAIN', 'SESSION_COOKIE_PATH', 'SESSION_COOKIE_HTTPONLY', 'SESSION_COOKIE_SECURE', 'SESSION_COOKIE_SAMESITE', 'SESSION_REFRESH_EACH_REQUEST', 'MAX_CONTENT_LENGTH', 'SEND_FILE_MAX_AGE_DEFAULT', 'TRAP_BAD_REQUEST_ERRORS', 'TRAP_HTTP_EXCEPTIONS', 'EXPLAIN_TEMPLATE_LOADING', 'PREFERRED_URL_SCHEME', 'PREFERRED_URL_SCHEME', 'MAX_COOKIE_SIZE']
for keyword in unwanted_keywords:
    app.config.pop(keyword, None)

# Initialize Flask-MySQLdb
mysql = pymysql.connect(
    host=app.config['mysql_host'],
    user=app.config['mysql_user'],
    password=app.config['mysql_password'],
    db=app.config['mysql_db'],
    cursorclass=pymysql.cursors.DictCursor
)

# Initialize Flask-Mail (if needed)
# mail = Mail(app)

@app.route("/", methods=["GET", "POST"])
def login():
    error_message = None

    if 'user' in session:
        return redirect("/dashboard")

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Fetch user from MySQL database
        with mysql.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session["user"] = email
            return redirect("/dashboard")
        else:
            error_message = "Invalid email or password."
            flash(error_message, 'error')

    return render_template('login.html', error=error_message)

@app.route("/dashboard")
def dashboard():
    if 'user' in session:
        # Fetch user information from MySQL database
        with mysql.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (session['user'],))
            user_info = cursor.fetchone()

        return render_template('dashboard.html', user=user_info)
    else:
        return redirect("/index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error_message = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')

        # Insert user into MySQL database
        with mysql.cursor() as cursor:
            try:
                cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
                mysql.commit()
                flash("Registration successful! You can now log in.", 'success')
                return redirect("/")
            except pymysql.IntegrityError:
                error_message = "Email already exists. Please choose a different one."
                flash(error_message, 'error')

    return render_template('register.html', error=error_message)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


# The rest of your password reset functionality can be adapted similarly.

if __name__ == "__main__":
    app.run(debug=True)
