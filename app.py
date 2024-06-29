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
        title = request.form.get("title")
        type_of_crime = request.form.get("type_of_crime")
        severity = request.form.get("severity")
        description = request.form.get("description")
        file = request.files['media']
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        reporter_id =  session["id"]
        date = request.form.get("date")
        if type_of_crime == "" or severity == "" or description == "" or latitude == "" or longitude == "":
            return render_template("report.html")
        if file and allowed_name(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join('report-images', filename))

            db.execute("INSERT INTO Crime_Reports (title, crime_type, description, reporter_id, severity, latitude, longitude, date, photo_ref) VALUES(?,?,?,?,?,?,?,?,?)",
                       title,type_of_crime,description,
                       reporter_id,severity,latitude,
                       longitude,date, filename)
            return redirect("/home")    
        else:
            return render_template("report.html", error="Invalid username or file")
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


@app.route('/src')
@login_required
def src():
    return render_template("search.html")

@app.route('/search')
@login_required
def search_reports():
    try:
        # Get query parameters
        query_params = request.args.to_dict()

        # Extract latitude and longitude from parameters
        latitude = float(query_params.get('lat', 0))
        longitude = float(query_params.get('lng', 0))

        # SQL query to find reports around given location within a certain radius
        sql = """
            SELECT * FROM Crime_Reports 
            WHERE 
                latitude BETWEEN ? AND ? AND 
                longitude BETWEEN ? AND ? AND 
                (latitude - ?) * (latitude - ?) + (longitude - ?) * (longitude - ?) <= ? * ?
        """

        # Parameters for the SQL query (adjust radius as needed, here set to 0.01 degrees approx. 1.1 km)
        radius = 0.05
        params = [
            latitude - radius, latitude + radius,
            longitude - radius, longitude + radius,
            latitude, latitude,
            longitude, longitude,
            radius, radius
        ]

        # Optional additional filters based on user input
        if 'q' in query_params and query_params['q']:
            sql += " AND (Title LIKE ? OR description LIKE ?)"
            params.extend(['%' + query_params['q'] + '%', '%' + query_params['q'] + '%'])

        if 'date' in query_params and query_params['date']:
            sql += " AND Date = ?"
            params.append(query_params['date'])

        if 'crime_type' in query_params and query_params['crime_type']:
            sql += " AND crime_type = ?"
            params.append(query_params['crime_type'])

        # Execute the query
        rows = db.execute(sql, *params)

        # Prepare JSON response
        reports = []
        for row in rows:
            report = {
                'report_id': row['report_id'],
                'Title': row['Title'],
                'crime_type': row['crime_type'],
                'description': row['description'],
                'reporter_id': row['reporter_id'],
                'severity': row['severity'],
                'latitude': row['latitude'],
                'longitude': row['longitude'],
                'status': row['status'],
                'Date': row['Date']
            }
            reports.append(report)

        return jsonify(reports)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

#app.run(host="0.0.0.0", port=50100, debug=True, ssl_context="adhoc")
