import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session.get("user_id")
    accounts = db.execute("SELECT COUNT(*) FROM users WHERE id = ?", user_id)[0]['COUNT(*)']
    if accounts == 1:
        shares_owned = db.execute("SELECT shares, symbol from purchases WHERE user_id = ?", user_id)
        users = db.execute("SELECT symbol, name, shares, price, total FROM purchases WHERE user_id = ?;", user_id)
        balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        for purchase in shares_owned:
            if purchase['shares'] == 0:
                symbol = purchase['symbol']
                db.execute("DELETE FROM purchases WHERE symbol = ? AND user_id = ?", symbol, user_id)

        return render_template("portfolio.html", purchases=users, balance=usd(balance[0]['cash']))

    else:
        return redirect("/register")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Enter the number of shares")

        user_id = session.get("user_id")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", (user_id,))
        date = datetime.now().date()
        time = datetime.now().time()

        if not symbol:
            return apology("Enter a Symbol")
        elif lookup(symbol) == None:
            return apology("Symbol not Available")

        if shares < 1:
            return apology("Enter a Positive Number")

        symbols = [row['symbol'] for row in db.execute("SELECT symbol FROM purchases WHERE user_id = ?", user_id)]

        if symbol in symbols:
            db.execute("UPDATE purchases SET shares = shares + 1 WHERE symbol = ? AND user_id = ?", symbol, user_id)
            cost = shares * quote['price']
            balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
            if cost > balance:
                return apology("You have insufficient balance to complete your purchase")
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, user_id)
            db.execute("UPDATE purchases SET total = total + ? WHERE user_id = ? AND symbol = ?", cost, user_id, symbol )
            db.execute("INSERT INTO history (symbol, name, shares, price, purchase, date, time, user_id) values(?, ?, ?, ?, ?, ?, ?, ?)", symbol, quote['name'], shares, usd(quote['price']), "Bought", date, time, user_id)


        else:
            cost = shares * quote['price']
            total = quote['price'] * shares
            balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
            if cost > balance:
                return apology("You have insufficient balance to complete your purchase")
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, user_id)
            db.execute("INSERT INTO purchases (symbol, name, shares, price, total, user_id) values(?, ?, ?, ?, ?, ?)", symbol, quote['name'], shares, usd(quote['price']), total, user_id)
            db.execute("INSERT INTO history (symbol, name, shares, price, purchase, date, time, user_id) values(?, ?, ?, ?, ?, ?, ?, ?)", symbol, quote['name'], shares, usd(quote['price']), "Bought", date, time, user_id)


        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session.get("user_id")
    history = db.execute("SELECT * FROM history WHERE user_id = ?", user_id)
    return render_template("history.html", history=history)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Enter a Symbol")
        elif lookup(symbol) == None:
            return apology("Symbol not Available")
        quote = lookup(symbol)

        return render_template("quoted.html", name=quote['name'], symbol=quote['symbol'], price=quote['price'])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)

        if not username:
            return apology("username required")

        if len(password) < 8:
            return apology("Password must be at least 8 characters")

        if confirmation != password:
            return apology("Passwords do not match!")

        usernames = [user['username'] for user in db.execute("SELECT username FROM users;")]
        if username in usernames:
            return apology("Username already taken!")

        db.execute("INSERT INTO users (username, hash) values(?, ?)", username, hash)
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == 'POST':
        """Sell shares of stock"""
        symbol = request.form.get("symbol")
        user_id = session.get("user_id")
        shares = int(request.form.get("shares"))
        stocks_owned = [row['symbol'] for row in db.execute("SELECT symbol FROM purchases WHERE user_id = ?", user_id)]
        shares_owned = db.execute("SELECT shares from purchases WHERE user_id = ? AND symbol = ?", user_id, symbol)
        date = datetime.now().date()
        time = datetime.now().time()


        if not symbol:
            return apology("Please enter a symbol")
        elif symbol not in stocks_owned:
            return apology("You dont own any shares of this stock!")

        if not shares:
            return apology("Please Enter The number of shares you want to sell!")
        elif shares > shares_owned[0]['shares']:
            return apology("You dont have enough shares in your possession to sell")

        quote = lookup(symbol)
        cost = quote['price'] * shares
        if shares_owned[0]['shares'] > 1:
            db.execute("UPDATE purchases SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, user_id, symbol)
            db.execute("UPDATE purchases SET total = total - ? WHERE user_id = ? AND symbol = ?", cost, user_id, symbol)
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cost, user_id)
            db.execute("INSERT INTO history (symbol, name, shares, price, purchase, date, time, user_id) values(?, ?, ?, ?, ?, ?, ?, ?)", symbol, quote['name'], shares, usd(quote['price']), "Sold", date, time, user_id)


        elif shares_owned[0]['shares'] == 1:
            db.execute("DELETE FROM purchases WHERE symbol = ? AND user_id = ?", symbol, user_id)
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cost, user_id)
            db.execute("INSERT INTO history (symbol, name, shares, price, purchase, date, time, user_id) values(?, ?, ?, ?, ?, ?, ?, ?)", symbol, quote['name'], shares, usd(quote['price']), "Sold", date, time, user_id)

        return redirect("/")

    else:
        return render_template("sell.html")

@app.route("/clear", methods = ["POST"])
def clear():
    user_id = session.get("user_id")
    db.execute("DELETE FROM history WHERE user_id = ?", user_id)
    return redirect("/history")

