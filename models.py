from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

MAX_FAILED_ATTEMPTS = 3
LOCK_MINUTES = 5


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False, default="customer")  # admin / customer
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    pin_hash = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    must_change_pin = db.Column(db.Boolean, nullable=False, default=True)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    transactions = db.relationship("Transaction", backref="user", lazy=True)

    def set_pin(self, pin):
        self.pin_hash = generate_password_hash(pin)

    def check_pin(self, pin):
        return check_password_hash(self.pin_hash, pin)

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def register_failed_attempt(self):
        self.failed_attempts += 1
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
            self.failed_attempts = 0
            return True  # now locked
        return False

    def reset_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # deposit / withdraw
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    balance_after = db.Column(db.Numeric(12, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)