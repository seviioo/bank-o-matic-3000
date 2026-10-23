import os
import secrets
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, g

from models import db, User, Transaction, AuditLog

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

db_url = os.getenv("DATABASE_URL", "sqlite:///bank.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Security: session expires after 3 minutes of inactivity
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=3)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BANK_NAME = os.getenv("BANK_NAME", "Bank-O-Matic 3000")
MAX_AMOUNT = Decimal("1000000")

db.init_app(app)


# ---------- Helpers ----------

def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr


def log_event(event, user_id=None, details=None, commit=True):
    db.session.add(AuditLog(user_id=user_id, event=event, details=details, ip_address=client_ip()))
    if commit:
        db.session.commit()


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            session.clear()
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        g.user = user
        # Force PIN change if still using the default PIN
        if user.must_change_pin and request.endpoint != "change_pin":
            flash("For your security, please change your default PIN first.", "error")
            return redirect(url_for("change_pin"))
        return f(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user.role != role:
                flash("You are not allowed to open that page.", "error")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def generate_account_number():
    while True:
        number = "BOM" + "".join(secrets.choice("0123456789") for _ in range(8))
        if not User.query.filter_by(account_number=number).first():
            return number


def valid_pin(pin):
    return pin.isdigit() and len(pin) == 4


def peso(value):
    return f"₱{Decimal(value):,.2f}"


@app.context_processor
def inject_globals():
    return {"bank_name": BANK_NAME, "peso": peso, "current_user": current_user()}


@app.after_request
def no_cache(response):
    # Security: stop the browser from showing old pages after logout (back button)
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------- Auth ----------

@app.route("/")
def home():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        account = request.form.get("account_number", "").strip().upper()
        pin = request.form.get("pin", "").strip()
        user = User.query.filter_by(account_number=account).first()

        if user and user.is_locked():
            log_event("login_blocked_locked", user.id)
            flash("This account is temporarily locked. Please try again in a few minutes.", "error")
            return render_template("login.html")

        if user and user.check_pin(pin):
            user.reset_attempts()
            session.clear()
            session["user_id"] = user.id
            session["role"] = user.role
            session.permanent = True
            log_event("login_success", user.id)
            return redirect(url_for("home"))

        if user:
            locked = user.register_failed_attempt()
            log_event("account_locked" if locked else "login_failed", user.id)
            if locked:
                flash("Too many wrong attempts. Account locked for 5 minutes.", "error")
                return render_template("login.html")
        else:
            log_event("login_failed_unknown", None, f"Account tried: {account[:20]}")

        flash("Invalid account number or PIN.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    user = current_user()
    if user:
        log_event("logout", user.id)
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/change-pin", methods=["GET", "POST"])
@login_required
def change_pin():
    user = g.user
    if request.method == "POST":
        current = request.form.get("current_pin", "").strip()
        new = request.form.get("new_pin", "").strip()
        confirm = request.form.get("confirm_pin", "").strip()

        if not user.check_pin(current):
            log_event("pin_change_failed", user.id, "Wrong current PIN")
            flash("Your current PIN is incorrect.", "error")
        elif not valid_pin(new):
            flash("New PIN must be exactly 4 digits.", "error")
        elif new != confirm:
            flash("New PIN and confirmation do not match.", "error")
        elif new == current:
            flash("New PIN must be different from your current PIN.", "error")
        else:
            user.set_pin(new)
            user.must_change_pin = False
            log_event("pin_changed", user.id)
            flash("PIN changed successfully.", "success")
            return redirect(url_for("home"))
    return render_template("change_pin.html")


# ---------- Admin ----------

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    customers = User.query.filter_by(role="customer").order_by(User.created_at.desc()).all()
    return render_template("admin_dashboard.html", customers=customers)


@app.route("/admin/create-customer", methods=["POST"])
@role_required("admin")
def create_customer():
    name = request.form.get("full_name", "").strip()
    default_pin = request.form.get("default_pin", "").strip()

    if not name or len(name) > 100:
        flash("Please enter the customer's full name (max 100 characters).", "error")
    elif not valid_pin(default_pin):
        flash("Default PIN must be exactly 4 digits.", "error")
    else:
        customer = User(
            role="customer",
            account_number=generate_account_number(),
            full_name=name,
            balance=0,
            must_change_pin=True,
        )
        customer.set_pin(default_pin)
        db.session.add(customer)
        db.session.flush()
        log_event("customer_created", g.user.id, f"Created {customer.account_number} ({name})", commit=False)
        db.session.commit()
        flash(f"Customer created. Account number: {customer.account_number}", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logs")
@role_required("admin")
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("admin_logs.html", logs=logs)


# ---------- Customer ----------

@app.route("/dashboard")
@role_required("customer")
def dashboard():
    txs = (Transaction.query.filter_by(user_id=g.user.id)
           .order_by(Transaction.created_at.desc()).limit(20).all())
    return render_template("dashboard.html", transactions=txs)


@app.route("/transaction", methods=["POST"])
@role_required("customer")
def transaction():
    user = g.user
    tx_type = request.form.get("type", "")
    raw_amount = request.form.get("amount", "").strip()
    pin = request.form.get("pin", "").strip()

    if tx_type not in ("deposit", "withdraw"):
        flash("Invalid transaction type.", "error")
        return redirect(url_for("dashboard"))

    # Security: the PIN must be re-entered for every transaction
    if not user.check_pin(pin):
        locked = user.register_failed_attempt()
        log_event("transaction_pin_failed", user.id, f"Attempted {tx_type}")
        if locked:
            session.clear()
            flash("Too many wrong PIN attempts. Account locked for 5 minutes.", "error")
            return redirect(url_for("login"))
        flash("Incorrect PIN. Transaction cancelled.", "error")
        return redirect(url_for("dashboard"))
    user.failed_attempts = 0

    try:
        amount = Decimal(raw_amount).quantize(Decimal("0.01"))
        if not amount.is_finite() or amount <= 0 or amount > MAX_AMOUNT:
            raise InvalidOperation
    except InvalidOperation:
        flash("Enter a valid amount greater than 0 (maximum ₱1,000,000).", "error")
        return redirect(url_for("dashboard"))

    if tx_type == "withdraw" and amount > user.balance:
        log_event("withdraw_rejected", user.id, f"Insufficient funds for {peso(amount)}")
        flash("Insufficient balance.", "error")
        return redirect(url_for("dashboard"))

    user.balance = user.balance + amount if tx_type == "deposit" else user.balance - amount
    db.session.add(Transaction(user_id=user.id, type=tx_type, amount=amount, balance_after=user.balance))
    log_event(tx_type, user.id, f"{peso(amount)}; new balance {peso(user.balance)}", commit=False)
    db.session.commit()

    word = "Deposited" if tx_type == "deposit" else "Withdrew"
    flash(f"{word} {peso(amount)} successfully. New balance: {peso(user.balance)}", "success")
    return redirect(url_for("dashboard"))


# ---------- Startup ----------

def init_db():
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        admin = User(role="admin", account_number="ADMIN", full_name="Bank Administrator",
                     balance=0, must_change_pin=True)
        admin.set_pin(os.getenv("ADMIN_PIN", "1234"))
        db.session.add(admin)
        db.session.commit()


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)