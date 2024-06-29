import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import shutil
from helpers import login_required, allowed_name

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/",methods=["GET"])
@login_required
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            return render_template("login.html", error="Must provide username!")

        # Ensure password was submitted
        elif not password:
            return render_template("login.html", error="Must provide password!")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM Users WHERE username = ?", username
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], password
        ):
            return render_template("login.html", error="Invalid username or password!")

        ids = db.execute("SELECT * FROM Users WHERE username = (?)", username)
        
        # Remember which user has logged in and then redirect user
        session["role"] = rows[0]["role"]
        session["username"] = username
        session["id"] = ids[0]["id"]
        return redirect("/home")
        
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET","POST"])
def register():
    if(request.method == "POST"):
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        vpassword = request.form.get("vpassword")
        contact = request.form.get("contact")
        role = request.form.get("role")
        #file = request.files['photo']
        if name == "" or username == "" or password == "" or contact == "":
            return render_template("register.html", error="Name/Username/Password/Contact is missing!")

        if len(contact) != 10:
            return render_template("register.html", error = "Contact invalid!")
        if password != vpassword:
            return render_template("register.html",error="Password verification failed!")

        entries = db.execute("SELECT * FROM Users WHERE username = ?", (username))
        if len(entries) != 0:
            return render_template("register.html",error="Username already exists!")

        hashed_password = generate_password_hash(password)
        
        # if file and allowed_name(file.filename):
        #     filename = secure_filename(file.filename)
        #     name, ext = os.path.splitext(filename)
        #     new_name = username + ext
        #     file.save(os.path.join('students-photos', new_name))


        db.execute(
            "INSERT INTO Users (username, name, hash, role, contact) VALUES (:u, :n, :h, :r, :c)",
            u=username,
            n=name,
            h=hashed_password,
            r=int(role),
            c=contact
        )

        ids = db.execute("SELECT * FROM Users WHERE username = (?)", username)
        session["username"] = username
        session["role"] = int(role)
        session["id"] = ids[0]["id"]
        return redirect("/home")
    else:
        return render_template("register.html")



@app.route("/home")
@login_required
def home():
    return render_template("dashboard.html")

@app.route("/report", methods=["GET","POST"])
@login_required
def report():
    if request.method == "POST":
        type_of_crime = request.form.get("type_of_crime")
        severity = request.form.get("severity")
        description = request.form.get("description")
        media = request.form.get("media")
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        reporter_id =  session["id"]
        if type_of_crime == "" or severity == "" or description == "" or latitude == "" or longitude == "":
            return render_template("report.html")
        else:
            db.execute("INSERT INTO Crime_Reports (crime_type, description, reporter_id, severity, latitude, longitude) VALUES(?,?,?,?,?,?)",
                       type_of_crime,
                       description,
                       reporter_id,
                       severity,
                       latitude,
                       longitude)
            return redirect("/home")        
    else:
        return render_template("report.html")
    
@app.route('/get_crime_reports')
def get_crime_reports():
    rows = db.execute('SELECT * FROM crime_reports')
    crime_reports = [dict(row) for row in rows]
    return jsonify(crime_reports)

@app.route('/reports/<reportId>')
def reports(reportId):
    rows = db.execute('SELECT * FROM Crime_Reports WHERE report_id = ?', (reportId))[0]
    return jsonify(rows)




#app.run(host="0.0.0.0", port=50100, debug=True, ssl_context="adhoc")