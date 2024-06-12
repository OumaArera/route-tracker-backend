from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy import ForeignKey
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(200), nullable=False)
    middle_name = db.Column(db.String(200), nullable=True)
    last_name = db.Column(db.String(200), nullable=False)
    avatar = db.Column(BYTEA, nullable=True)
    staff_no = db.Column(db.Integer, nullable=False, unique=True)
    national_id_no = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="active")  # active/blocked. 
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    last_password_change = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))


class RoutePlan(db.Model):

    __tablename__ = "route_plans"

    id = db.Column(db.Integer, primary_key=True)
    merchandiser_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    manager_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    date_range = db.Column(JSON, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False)

    merchandiser = db.relationship('User', foreign_keys=[merchandiser_id], backref=db.backref('route_plans', lazy=True))
    manager = db.relationship('User', foreign_keys=[manager_id], backref=db.backref('assigned_route_plans', lazy=True))



class Location(db.Model):

    __tablename__ = "locations"

    id = db.Column(db.Integer, primary_key=True)
    merchandiser_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    merchandiser = db.relationship('User', backref=db.backref('locations', lazy=True))

  

class Notification(db.Model):

    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    status = db.Column(db.String(20), nullable=False)
    recipient = db.relationship('User', backref=db.backref('notifications', lazy=True))


class ActivityLog(db.Model):

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    user = db.relationship('User', backref=db.backref('activity_logs', lazy=True))


class KeyPerformaceIndicator(db.Model):

    __tablename__ = "key_performance_indicators"

    id = db.Column(db.Integer, primary_key=True)
    facility_id = db.Column(db.Integer, ForeignKey("facilities.id"), nullable=False)
    performance_metric = db.Column(JSON, nullable=False)

    facility = db.relationship("User", backref=db.backref('key_performance_indicators', lazy=True))


class Response(db.Model):
    __tablename__ = "responses"

    id = db.Column(db.Integer, primary_key=True)
    merchandiser_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    manager_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    response = db.Column(JSON, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    kpi_id = db.Column(db.Integer, ForeignKey("key_performance_indicators.id"), nullable=False)

    key_pi_ais = db.relationship("KeyPerformaceIndicator", backref=db.backref('responses', lazy=True))
    merchandiser = db.relationship('User', foreign_keys=[merchandiser_id], backref=db.backref('responses', lazy=True))
    manager = db.relationship('User', foreign_keys=[manager_id], backref=db.backref('responses', lazy=True))




class Facility(db.Model):

    __tablename__ = "facilities"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(200), nullable=False)
    manager_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)

    manager = db.relationship("User", backref=db.backref('facilities', lazy=True))



class MerchandiserPerformance(db.Model):
    __tablename__ = "merchandiser_performances"

    id = db.Column(db.Integer, primary_key=True)
    merchandiser_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    k_p_i_id = db.Column(db.Integer, ForeignKey("key_performance_indicators.id"), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    day = db.Column(db.String(50), nullable=False)
    performance = db.Column(JSON, nullable=False) #parse

    merchandiser = db.relationship('User', backref=db.backref('merchandiser_performances', lazy=True))
    kpi = db.relationship('KeyPerformaceIndicator', backref=db.backref('merchandiser_performances', lazy=True))



class AssignedMerchandiser(db.Model):
    __tablename__ = "assigned_merchandisers"

    id = db.Column(db.Integer, primary_key=True)
    manager_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    merchandiser_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    month = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
     

    merchandiser = db.relationship('User', foreign_keys=[merchandiser_id], backref=db.backref('assigned_merchandisers', lazy=True))
    manager = db.relationship('User', foreign_keys=[manager_id], backref=db.backref('assigned_merchandisers', lazy=True))


