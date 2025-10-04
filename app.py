"""
Enhanced Blood Donation Ecosystem - FIXED VERSION
All features working: OTP, SMS, Email, GPS, Admin Panel
"""
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import jwt
import json
import hashlib
import secrets
from functools import wraps
import os
from werkzeug.utils import secure_filename
import random
import string

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = '07f4fac7a199f2037f97dc6af2ecb68f6c0655d1c44fa5451829de93fcddce5a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blood_donation.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/documents'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Email Configuration - USE APP PASSWORD NOT REGULAR PASSWORD!
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aatif.shaikh2004@gmail.com'
app.config['MAIL_PASSWORD'] = 'rgsohydtlhwdzjtm'  # Generate from Google Account Settings
app.config['MAIL_DEFAULT_SENDER'] = 'aatif.shaikh2004@gmail.com'

# Twilio Configuration (Optional)
TWILIO_ACCOUNT_SID = 'ACed7a608054a0f16dc0d172d6b928182e'
TWILIO_AUTH_TOKEN = '3a81b38cf2de9df7411fe8ed6fce19f8'
TWILIO_PHONE_NUMBER = '+17604936584'

CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== DATABASE MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='donor')
    is_approved = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    phone = db.Column(db.String(20))
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    blood_type = db.Column(db.String(5), nullable=False)
    phone = db.Column(db.String(20))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    address = db.Column(db.Text)
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    pincode = db.Column(db.String(10))
    aadhaar_number = db.Column(db.String(20))
    aadhaar_file = db.Column(db.String(200))
    last_donation = db.Column(db.DateTime)
    total_donations = db.Column(db.Integer, default=0)
    points = db.Column(db.Integer, default=0)
    badges = db.Column(db.Text)
    availability_status = db.Column(db.String(20), default='available')
    user = db.relationship('User', backref='donor_profile')

class BloodRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hospital_name = db.Column(db.String(200), nullable=False)
    blood_type = db.Column(db.String(5), nullable=False)
    units_needed = db.Column(db.Integer, nullable=False)
    units_fulfilled = db.Column(db.Integer, default=0)
    urgency = db.Column(db.String(20))
    patient_name = db.Column(db.String(100))
    contact_person = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    fulfilled_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class DonationResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('blood_request.id'))
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
    units_donated = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='pending')
    donation_date = db.Column(db.DateTime)
    certificate_issued = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    donor = db.relationship('Donor', backref='donations')
    request = db.relationship('BloodRequest', backref='responses')

class BloodInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blood_type = db.Column(db.String(5), nullable=False, unique=True)
    units_available = db.Column(db.Integer, default=0)
    expiry_date = db.Column(db.DateTime)
    temperature = db.Column(db.Float, default=4.0)
    location = db.Column(db.String(200))
    blockchain_hash = db.Column(db.String(200))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    type = db.Column(db.String(50))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Blockchain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(200))
    hash = db.Column(db.String(200))
    nonce = db.Column(db.Integer)

# ==================== HELPER FUNCTIONS ====================

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email_alert(to_email, subject, body):
    """Send email with fallback to console"""
    try:
        if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'] != 'YOUR_16_CHAR_APP_PASSWORD_HERE':
            msg = Message(subject, recipients=[to_email])
            msg.body = body
            msg.html = f"<html><body><div style='padding:20px;'><h2>{subject}</h2><p>{body}</p></div></body></html>"
            mail.send(msg)
            print(f"✅ Email sent to {to_email}")
            return True
    except Exception as e:
        print(f"❌ Email error: {e}")
    
    # Fallback: Print to console
    print(f"\n{'='*60}")
    print(f"📧 EMAIL TO: {to_email}")
    print(f"📧 SUBJECT: {subject}")
    print(f"📧 BODY: {body}")
    print(f"{'='*60}\n")
    return True

def send_sms_alert(to_phone, message):
    """Send SMS with fallback to console"""
    try:
        from twilio.rest import Client
        if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            client.messages.create(
                body=message,
                from_=TWILIO_PHONE_NUMBER,
                to=to_phone
            )
            print(f"✅ SMS sent to {to_phone}")
            return True
    except Exception as e:
        print(f"❌ SMS error: {e}")
    
    # Fallback: Print to console
    print(f"\n{'='*60}")
    print(f"📱 SMS TO: {to_phone}")
    print(f"📱 MESSAGE: {message}")
    print(f"{'='*60}\n")
    return True

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token missing'}), 401
        
        try:
            token = token.split()[1] if ' ' in token else token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except Exception as e:
            print(f"Token error: {e}")
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    
    return decorated

def calculate_distance(lat1, lon1, lat2, lon2):
    """Haversine formula for distance calculation"""
    from math import radians, sin, cos, sqrt, atan2
    R = 6371
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

# ==================== AUTH ROUTES ====================

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        otp = generate_otp()
        
        user = User(
            email=data['email'],
            password=hashed_password,
            role=data.get('role', 'donor'),
            phone=data.get('phone'),
            otp=otp,
            otp_expiry=datetime.utcnow() + timedelta(minutes=10),
            is_approved=False,
            is_verified=False
        )
        
        db.session.add(user)
        db.session.flush()
        
        donor = Donor(
            user_id=user.id,
            name=data.get('name'),
            blood_type=data.get('blood_type'),
            phone=data.get('phone'),
            badges=json.dumps([])
        )
        
        db.session.add(donor)
        db.session.commit()
        
        # Send OTP
        send_email_alert(
            user.email,
            "Blood Donation - Email Verification OTP",
            f"Your OTP for email verification is: {otp}. Valid for 10 minutes."
        )
        
        if user.phone:
            send_sms_alert(
                user.phone,
                f"Your Blood Donation OTP is: {otp}. Valid for 10 minutes."
            )
        
        return jsonify({
            'message': 'Registration successful! Check your email/SMS for OTP.',
            'user_id': user.id
        }), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.json
        user = User.query.get(data['user_id'])
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.is_verified:
            return jsonify({'message': 'Already verified'}), 400
        
        if user.otp != data['otp']:
            return jsonify({'message': 'Invalid OTP'}), 400
        
        if datetime.utcnow() > user.otp_expiry:
            return jsonify({'message': 'OTP expired'}), 400
        
        user.is_verified = True
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        
        return jsonify({
            'message': 'OTP verified successfully!',
            'verified': True
        }), 200
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    try:
        data = request.json
        user = User.query.get(data['user_id'])
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()
        
        send_email_alert(user.email, "New OTP", f"Your new OTP is: {otp}")
        if user.phone:
            send_sms_alert(user.phone, f"New OTP: {otp}")
        
        return jsonify({'message': 'New OTP sent'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/complete-registration', methods=['POST'])
def complete_registration():
    try:
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        
        if not user or not user.is_verified:
            return jsonify({'message': 'User not verified'}), 400
        
        donor = Donor.query.filter_by(user_id=user_id).first()
        if not donor:
            return jsonify({'message': 'Donor profile not found'}), 400
        
        donor.address = request.form.get('address')
        donor.city = request.form.get('city', '')
        donor.state = request.form.get('state', '')
        donor.pincode = request.form.get('pincode', '')
        donor.latitude = float(request.form.get('latitude', 0))
        donor.longitude = float(request.form.get('longitude', 0))
        donor.aadhaar_number = request.form.get('aadhaar_number')
        
        if 'aadhaar_file' in request.files:
            file = request.files['aadhaar_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{int(datetime.now().timestamp())}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                donor.aadhaar_file = filename
        
        db.session.commit()
        
        send_email_alert(
            user.email,
            "Registration Complete",
            f"Dear {donor.name}, Your registration is complete. Awaiting admin approval."
        )
        
        return jsonify({'message': 'Registration complete. Awaiting admin approval.'}), 201
    except Exception as e:
        print(f"Complete registration error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not bcrypt.check_password_hash(user.password, data['password']):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        if not user.is_verified:
            return jsonify({'message': 'Please verify your email first'}), 403
        
        if not user.is_approved and user.role != 'admin':
            return jsonify({'message': 'Account pending admin approval'}), 403
        
        token = jwt.encode({
            'user_id': user.id,
            'role': user.role,
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user_id': user.id,
            'role': user.role,
            'email': user.email
        }), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== DONOR ROUTES ====================

@app.route('/api/donor/profile', methods=['GET'])
@token_required
def get_donor_profile(current_user):
    try:
        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify({'message': 'Donor profile not found'}), 404
        
        return jsonify({
            'id': donor.id,
            'name': donor.name,
            'blood_type': donor.blood_type,
            'phone': donor.phone,
            'address': donor.address,
            'city': donor.city,
            'state': donor.state,
            'latitude': donor.latitude,
            'longitude': donor.longitude,
            'total_donations': donor.total_donations,
            'points': donor.points,
            'badges': json.loads(donor.badges or '[]'),
            'availability_status': donor.availability_status,
            'last_donation': donor.last_donation.isoformat() if donor.last_donation else None
        }), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/donor/update-location', methods=['POST'])
@token_required
def update_donor_location(current_user):
    try:
        data = request.json
        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify({'message': 'Donor not found'}), 404
        
        donor.latitude = data['latitude']
        donor.longitude = data['longitude']
        db.session.commit()
        
        return jsonify({'message': 'Location updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/donor/toggle-availability', methods=['POST'])
@token_required
def toggle_availability(current_user):
    try:
        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify({'message': 'Donor not found'}), 404
        
        donor.availability_status = 'unavailable' if donor.availability_status == 'available' else 'available'
        db.session.commit()
        
        return jsonify({
            'message': 'Availability updated',
            'status': donor.availability_status
        }), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== DONATION ROUTES ====================

@app.route('/api/donations/respond', methods=['POST'])
@token_required
def respond_to_request(current_user):
    try:
        data = request.json
        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify({'message': 'Donor not found'}), 404
        
        blood_request = BloodRequest.query.get(data['request_id'])
        if not blood_request:
            return jsonify({'message': 'Request not found'}), 404
        
        units = data.get('units', 1)
        
        response = DonationResponse(
            request_id=blood_request.id,
            donor_id=donor.id,
            units_donated=units,
            status='confirmed',
            donation_date=datetime.utcnow()
        )
        db.session.add(response)
        
        blood_request.units_fulfilled += units
        if blood_request.units_fulfilled >= blood_request.units_needed:
            blood_request.status = 'fulfilled'
            blood_request.fulfilled_at = datetime.utcnow()
        
        donor.last_donation = datetime.utcnow()
        donor.total_donations += 1
        donor.points += 100
        
        # Update inventory
        inventory = BloodInventory.query.filter_by(blood_type=donor.blood_type).first()
        if inventory:
            inventory.units_available += units
            inventory.last_updated = datetime.utcnow()
        
        # Award badges
        badges = json.loads(donor.badges or '[]')
        if donor.total_donations == 1 and 'first_hero' not in badges:
            badges.append('first_hero')
        if donor.total_donations == 5 and 'bronze_saver' not in badges:
            badges.append('bronze_saver')
        if donor.total_donations == 10 and 'silver_guardian' not in badges:
            badges.append('silver_guardian')
        if donor.total_donations == 25 and 'gold_champion' not in badges:
            badges.append('gold_champion')
        donor.badges = json.dumps(badges)
        
        db.session.commit()
        
        send_email_alert(
            current_user.email,
            "Thank You for Your Donation!",
            f"Dear {donor.name}, Thank you for donating {units} unit(s). You've earned 100 points!"
        )
        
        if donor.phone:
            send_sms_alert(donor.phone, f"Thank you! You now have {donor.total_donations} donations.")
        
        return jsonify({
            'message': 'Donation recorded successfully',
            'total_donations': donor.total_donations,
            'points': donor.points,
            'new_badges': badges
        }), 201
    except Exception as e:
        print(f"Donation error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/donations/my-donations', methods=['GET'])
@token_required
def get_my_donations(current_user):
    try:
        donor = Donor.query.filter_by(user_id=current_user.id).first()
        if not donor:
            return jsonify([]), 200
        
        donations = DonationResponse.query.filter_by(donor_id=donor.id).order_by(DonationResponse.created_at.desc()).all()
        
        return jsonify([{
            'id': d.id,
            'hospital': d.request.hospital_name,
            'units': d.units_donated,
            'date': d.created_at.isoformat(),
            'status': d.status
        } for d in donations]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== NOTIFICATION ROUTES ====================

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    try:
        notifications = Notification.query.filter_by(
            user_id=current_user.id
        ).order_by(Notification.created_at.desc()).limit(50).all()
        
        return jsonify([{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@token_required
def mark_notification_read(current_user, notification_id):
    try:
        notification = Notification.query.get(notification_id)
        if notification and notification.user_id == current_user.id:
            notification.is_read = True
            db.session.commit()
            return jsonify({'message': 'Marked as read'}), 200
        return jsonify({'message': 'Not found'}), 404
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== BLOOD REQUEST ROUTES ====================

@app.route('/api/requests/create', methods=['POST'])
@token_required
def create_blood_request(current_user):
    try:
        data = request.json
        
        request_obj = BloodRequest(
            hospital_name=data['hospital_name'],
            blood_type=data['blood_type'],
            units_needed=data['units_needed'],
            urgency=data['urgency'],
            patient_name=data.get('patient_name'),
            contact_person=data.get('contact_person'),
            contact_phone=data.get('contact_phone'),
            latitude=data.get('latitude', 0),
            longitude=data.get('longitude', 0),
            created_by=current_user.id
        )
        
        db.session.add(request_obj)
        db.session.commit()
        
        # Notify matching donors
        matching_donors = Donor.query.filter_by(
            blood_type=data['blood_type'],
            availability_status='available'
        ).all()
        
        notified = 0
        for donor in matching_donors:
            user = User.query.get(donor.user_id)
            if user and user.is_approved:
                # Create notification
                notification = Notification(
                    user_id=user.id,
                    title=f"🚨 Urgent: {data['blood_type']} Blood Needed",
                    message=f"{data['hospital_name']} needs {data['units_needed']} units. Urgency: {data['urgency'].upper()}",
                    type='blood_request'
                )
                db.session.add(notification)
                
                # Send email
                send_email_alert(
                    user.email,
                    "Urgent Blood Request",
                    f"Dear {donor.name}, {data['hospital_name']} urgently needs {data['blood_type']} blood. Login to respond."
                )
                
                # Send SMS
                if donor.phone:
                    send_sms_alert(
                        donor.phone,
                        f"Urgent: {data['blood_type']} needed at {data['hospital_name']}. Login to help!"
                    )
                notified += 1
        
        db.session.commit()
        
        return jsonify({
            'message': 'Request created',
            'request_id': request_obj.id,
            'donors_notified': notified
        }), 201
    except Exception as e:
        print(f"Request creation error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/requests/active', methods=['GET'])
def get_active_requests():
    try:
        requests = BloodRequest.query.filter_by(status='pending').order_by(BloodRequest.created_at.desc()).all()
        
        return jsonify([{
            'id': r.id,
            'hospital_name': r.hospital_name,
            'blood_type': r.blood_type,
            'units_needed': r.units_needed,
            'units_fulfilled': r.units_fulfilled,
            'urgency': r.urgency,
            'patient_name': r.patient_name,
            'contact_phone': r.contact_phone,
            'latitude': r.latitude,
            'longitude': r.longitude,
            'created_at': r.created_at.isoformat()
        } for r in requests]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/statistics', methods=['GET'])
@token_required
@admin_required
def get_admin_statistics(current_user):
    try:
        total_donors = Donor.query.count()
        approved_donors = User.query.filter_by(is_approved=True, role='donor').count()
        total_requests = BloodRequest.query.count()
        active_requests = BloodRequest.query.filter_by(status='pending').count()
        total_donations = DonationResponse.query.filter_by(status='confirmed').count()
        pending_approvals = User.query.filter_by(is_approved=False, is_verified=True).count()
        
        blood_types = db.session.query(
            Donor.blood_type,
            db.func.count(Donor.id)
        ).group_by(Donor.blood_type).all()
        
        recent_donations = DonationResponse.query.order_by(
            DonationResponse.created_at.desc()
        ).limit(10).all()
        
        return jsonify({
            'total_donors': total_donors,
            'approved_donors': approved_donors,
            'total_requests': total_requests,
            'active_requests': active_requests,
            'total_donations': total_donations,
            'pending_approvals': pending_approvals,
            'blood_type_distribution': [{'blood_type': bt, 'count': count} for bt, count in blood_types],
            'recent_activity': [{
                'donor': d.donor.name,
                'hospital': d.request.hospital_name,
                'units': d.units_donated,
                'date': d.created_at.isoformat()
            } for d in recent_donations]
        }), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/pending-users', methods=['GET'])
@token_required
@admin_required
def get_pending_users(current_user):
    try:
        users = User.query.filter_by(is_approved=False, is_verified=True).all()
        result = []
        
        for u in users:
            donor = Donor.query.filter_by(user_id=u.id).first()
            result.append({
                'id': u.id,
                'email': u.email,
                'role': u.role,
                'phone': u.phone,
                'created_at': u.created_at.isoformat(),
                'registration_time': u.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'donor_info': {
                    'name': donor.name if donor else None,
                    'blood_type': donor.blood_type if donor else None,
                    'address': donor.address if donor else None,
                    'city': donor.city if donor else None,
                    'state': donor.state if donor else None,
                    'latitude': donor.latitude if donor else None,
                    'longitude': donor.longitude if donor else None,
                    'aadhaar_number': donor.aadhaar_number if donor else None,
                    'aadhaar_file': donor.aadhaar_file if donor else None
                } if donor else None
            })
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/donors', methods=['GET'])
@token_required
@admin_required
def get_all_donors(current_user):
    try:
        donors = Donor.query.join(User).filter(User.is_approved == True).all()
        
        result = []
        for d in donors:
            result.append({
                'id': d.id,
                'name': d.name,
                'blood_type': d.blood_type,
                'phone': d.phone,
                'email': d.user.email,
                'address': d.address,
                'city': d.city,
                'state': d.state,
                'latitude': d.latitude,
                'longitude': d.longitude,
                'total_donations': d.total_donations,
                'points': d.points,
                'availability_status': d.availability_status,
                'last_donation': d.last_donation.isoformat() if d.last_donation else None,
                'registration_date': d.user.created_at.isoformat()
            })
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/approve-user/<int:user_id>', methods=['POST'])
@token_required
@admin_required
def approve_user(current_user, user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        user.is_approved = True
        db.session.commit()
        
        donor = Donor.query.filter_by(user_id=user_id).first()
        
        send_email_alert(
            user.email,
            "Account Approved!",
            f"Dear {donor.name if donor else 'User'}, Your account has been approved. You can now login and start donating blood!"
        )
        
        if user.phone:
            send_sms_alert(user.phone, "Your Blood Donation account has been approved! Login now.")
        
        return jsonify({'message': 'User approved successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/reject-user/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def reject_user(current_user, user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        donor = Donor.query.filter_by(user_id=user_id).first()
        if donor:
            db.session.delete(donor)
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User rejected'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/admin/inventory/update', methods=['POST'])
@token_required
@admin_required
def update_inventory(current_user):
    try:
        data = request.json
        
        inventory = BloodInventory.query.filter_by(blood_type=data['blood_type']).first()
        
        if not inventory:
            inventory = BloodInventory(blood_type=data['blood_type'])
            db.session.add(inventory)
        
        inventory.units_available = data.get('units_available', inventory.units_available)
        inventory.temperature = data.get('temperature', inventory.temperature)
        inventory.location = data.get('location', inventory.location)
        inventory.last_updated = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'message': 'Inventory updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/inventory/all', methods=['GET'])
def get_inventory():
    try:
        inventory = BloodInventory.query.all()
        
        return jsonify([{
            'id': i.id,
            'blood_type': i.blood_type,
            'units_available': i.units_available,
            'temperature': i.temperature,
            'location': i.location,
            'last_updated': i.last_updated.isoformat()
        } for i in inventory]), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/uploads/documents/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== BLOCKCHAIN ====================

def calculate_hash(index, timestamp, data, previous_hash, nonce=0):
    value = str(index) + str(timestamp) + str(data) + str(previous_hash) + str(nonce)
    return hashlib.sha256(value.encode()).hexdigest()

@app.route('/api/blockchain/verify', methods=['GET'])
def verify_blockchain():
    try:
        blocks = Blockchain.query.order_by(Blockchain.index).all()
        
        if len(blocks) == 0:
            return jsonify({'valid': True, 'total_blocks': 0}), 200
        
        for i, block in enumerate(blocks):
            if i == 0:
                continue
            
            calculated_hash = calculate_hash(
                block.index,
                block.timestamp,
                block.data,
                block.previous_hash,
                block.nonce
            )
            
            if calculated_hash != block.hash:
                return jsonify({'valid': False, 'error': f'Invalid hash at block {i}'}), 200
            
            if block.previous_hash != blocks[i-1].hash:
                return jsonify({'valid': False, 'error': f'Broken chain at block {i}'}), 200
        
        return jsonify({'valid': True, 'total_blocks': len(blocks)}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== INITIALIZATION ====================

@app.route('/api/init-db', methods=['GET', 'POST'])
def init_database():
    try:
        db.create_all()
        
        if not User.query.filter_by(email='admin@bloodbank.com').first():
            admin = User(
                email='admin@bloodbank.com',
                password=bcrypt.generate_password_hash('Admin@123').decode('utf-8'),
                role='admin',
                is_approved=True,
                is_verified=True
            )
            db.session.add(admin)
        
        blood_types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
        
        for bt in blood_types:
            if not BloodInventory.query.filter_by(blood_type=bt).first():
                inv = BloodInventory(
                    blood_type=bt,
                    units_available=random.randint(20, 100),
                    temperature=4.0,
                    location='Central Blood Bank'
                )
                db.session.add(inv)
        
        db.session.commit()
        
        return jsonify({'message': 'Database initialized successfully'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Server is running',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("\n" + "="*60)
        print("✅ Enhanced Blood Donation System Started!")
        print("="*60)
        print("\nFeatures: OTP, Email & SMS Alerts, GPS Tracking")
        print("Auto Inventory Management Active")
        print("\nAdmin Credentials:")
        print("Email: admin@bloodbank.com")
        print("Password: Admin@123")
        print("\nIMPORTANT: Configure Gmail App Password in code!")
        print("="*60 + "\n")
        
        app.run(debug=True, host='0.0.0.0', port=5000)