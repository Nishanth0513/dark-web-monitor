from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_unseen_breaches = db.Column(db.Boolean, default=False)


class MonitoredEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    last_checked = db.Column(db.DateTime, nullable=True)


class Breach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    breach_name = db.Column(db.String(255), nullable=False)
    breach_date = db.Column(db.DateTime, nullable=False)
    data_exposed = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    admin_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_unseen_breaches = db.Column(db.Boolean, default=False)


class OrgEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    last_checked = db.Column(db.DateTime, nullable=True)


class OrgBreach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    breach_name = db.Column(db.String(255), nullable=False)
    breach_date = db.Column(db.DateTime, nullable=False)
    data_exposed = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

