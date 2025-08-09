from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash 
import pymysql
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import smtplib
import random
import string
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize Flask app
app = Flask(__name__, static_folder='assets', template_folder='.')
app.secret_key = '123456789'  # Used for flash messages

# Email Configuration - UPDATE THESE WITH YOUR ACTUAL GMAIL SETTINGS
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'pathumdeeptha9@gmail.com'  # Your Gmail address
EMAIL_PASS = 'baqv ryaf zbll iyth'    # Your Gmail App Password (16 characters, no spaces)
EMAIL_FROM = 'pathumdeeptha9@gmail.com'  # Same as EMAIL_USER  

# Set to True when you have configured your actual email credentials above
EMAIL_ENABLED = True  # Change to True after updating credentials above

# MySQL Database Connection
def get_db_connection():
    """Get a database connection with error handling"""
    try:
        db = pymysql.connect(
            host="localhost",
            user="root",
            password="",
            database="web_app_db",
            autocommit=True,
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5
        )
        return db
    except pymysql.MySQLError as err:
        return None

# Initialize database connection
db = get_db_connection()
if db:
    cursor = db.cursor()
else:
    cursor = None

def ensure_db_connection():
    """Ensure database connection is alive"""
    global db, cursor
    try:
        if db:
            db.ping(reconnect=True)
        else:
            db = get_db_connection()
            if db:
                cursor = db.cursor()
    except:
        db = get_db_connection()
        if db:
            cursor = db.cursor()

# Helper function to generate verification code
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

# Helper function to send signup verification email
def send_signup_verification_email(to_email, verification_code, user_name):
    # If email is disabled, use console output for testing
    if not EMAIL_ENABLED:
        print(f"\n📧 SIGNUP EMAIL VERIFICATION SIMULATION 📧")
        print(f"To: {to_email}")
        print(f"User: {user_name}")
        print(f"Verification Code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return True
    
    # Check if email credentials are configured
    if EMAIL_USER == 'your-email@gmail.com' or EMAIL_PASS == 'your-app-password' or EMAIL_FROM == 'your-actual-email@gmail.com':
        print(f"\n❌ EMAIL NOT CONFIGURED ❌")
        print(f"Please update EMAIL_USER, EMAIL_PASS, and EMAIL_FROM in app.py")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = f"Arogya System <{EMAIL_FROM}>"
        msg['To'] = to_email
        msg['Subject'] = "🔐 Arogya - Complete Your Registration"
        
        # Enhanced HTML email body for signup
        html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; color: white;">
            <h1 style="margin: 0; font-size: 24px;">🏥 Arogya</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Healthcare Management System</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; margin: 20px 0;">
            <h2 style="color: #333; margin-top: 0;">Welcome {user_name}! 🎉</h2>
            
            <p>Thank you for signing up with Arogya! To complete your registration and activate your account, please verify your email address using the code below:</p>
            
            <div style="background: #fff; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                <h1 style="color: #667eea; font-size: 32px; margin: 0; letter-spacing: 5px; font-family: 'Courier New', monospace;">
                    {verification_code}
                </h1>
            </div>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;">
                    ⏰ <strong>Important:</strong> This code will expire in 10 minutes for security reasons.
                </p>
            </div>
            
            <div style="background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 5px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #0c5460;">
                    🔒 <strong>Account Security:</strong> Your account will be created only after successful email verification.
                </p>
            </div>
            
            <p>If you didn't create an account with Arogya, please ignore this email.</p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #666; font-size: 14px;">
                Best regards,<br>
                <strong>Arogya Team</strong><br>
                Healthcare Management System<br>
                Email sent to: {to_email}
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, to_email, text)
        server.quit()
        
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"\n❌ EMAIL AUTHENTICATION ERROR ❌")
        print(f"Please check your EMAIL_USER and EMAIL_PASS credentials")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except smtplib.SMTPConnectError as e:
        print(f"\n❌ EMAIL CONNECTION ERROR ❌")
        print(f"Unable to connect to email server")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except smtplib.SMTPServerDisconnected as e:
        print(f"\n❌ EMAIL SERVER DISCONNECTED ❌")
        print(f"Email server disconnected")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except smtplib.SMTPRecipientsRefused as e:
        print(f"\n❌ EMAIL RECIPIENTS REFUSED ❌")
        print(f"Email address {to_email} was rejected")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except smtplib.SMTPException as e:
        print(f"\n❌ EMAIL SMTP ERROR ❌")
        print(f"SMTP error occurred: {str(e)}")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except (ConnectionError, TimeoutError, OSError) as e:
        print(f"\n❌ EMAIL CONNECTION TIMEOUT ❌")
        print(f"Network connection error: {str(e)}")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False
        
    except Exception as e:
        print(f"\n❌ EMAIL UNEXPECTED ERROR ❌")
        print(f"Unexpected error: {str(e)}")
        print(f"For testing purposes, verification code: {verification_code}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return False

# Helper function to send email
def send_verification_email(to_email, verification_code, user_name):
    # If email is disabled, use console output for testing
    if not EMAIL_ENABLED:
        return True
    
    # Check if email credentials are configured
    if EMAIL_USER == 'your-email@gmail.com' or EMAIL_PASS == 'your-app-password' or EMAIL_FROM == 'your-actual-email@gmail.com':
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = f"Arogya System <{EMAIL_FROM}>"
        msg['To'] = to_email
        msg['Subject'] = "🔐 Arogya - Email Verification Code"
        
        # Enhanced HTML email body
        html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; color: white;">
            <h1 style="margin: 0; font-size: 24px;">🏥 Arogya</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Healthcare Management System</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; margin: 20px 0;">
            <h2 style="color: #333; margin-top: 0;">Hello {user_name}! 👋</h2>
            
            <p>Your verification code for Arogya login is:</p>
            
            <div style="background: #fff; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                <h1 style="color: #667eea; font-size: 32px; margin: 0; letter-spacing: 5px; font-family: 'Courier New', monospace;">
                    {verification_code}
                </h1>
            </div>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;">
                    ⏰ <strong>Important:</strong> This code will expire in 1 minute for security reasons.
                </p>
            </div>
            
            <p>If you didn't request this verification, please ignore this email.</p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #666; font-size: 14px;">
                Best regards,<br>
                <strong>Arogya Team</strong><br>
                Healthcare Management System<br>
                Email sent to: {to_email}
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, to_email, text)
        server.quit()
        
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        return False
        
    except smtplib.SMTPConnectError as e:
        return False
        
    except smtplib.SMTPServerDisconnected as e:
        return False
        
    except smtplib.SMTPRecipientsRefused as e:
        return False
        
    except smtplib.SMTPException as e:
        return False
        
    except (ConnectionError, TimeoutError, OSError) as e:
        return False
        
    except Exception as e:
        return False

# Route for Home Page (index.html)
@app.route('/')
def index():
    # Check if user is already logged in
    if 'nic' in session:
        return render_template('index.html')  # Show home page if logged in
    else:
        return redirect(url_for('login'))  # Redirect to login if not logged in

# Route for Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        device_fingerprint = request.form.get('device_fingerprint')
        device_name = request.form.get('device_name')
        location = request.form.get('location')
        ip_address = request.remote_addr

        # Validate login credentials with database
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user:
            db_password_hash = user[7]  # Ensure index 7 is for 'password_hash'
            email_verified = user[9] if len(user) > 9 else 0  # Check if email is verified

            if check_password_hash(db_password_hash, password):
                # Check if email is verified
                if not email_verified:
                    flash('Please verify your email address before logging in. Check your inbox for the verification email.', 'warning')
                    return redirect(url_for('login'))

                # Store NIC in session
                session['nic'] = user[0]  # NIC is the primary key

                # --- Check for Trusted Device First ---
                trusted_device = False
                
                # Check if device is trusted
                if device_fingerprint:
                    cursor.execute(
                        "SELECT trusted FROM user_devices WHERE nic = %s AND device_fingerprint = %s",
                        (user[0], device_fingerprint)
                    )
                    device = cursor.fetchone()
                    if device and device[0]:  # trusted == True
                        trusted_device = True
                        # Update last_used timestamp for trusted device
                        cursor.execute(
                            "UPDATE user_devices SET last_used = NOW() WHERE nic = %s AND device_fingerprint = %s",
                            (user[0], device_fingerprint)
                        )
                        db.commit()
                        
                        # Record login history for trusted device (not suspicious)
                        try:
                            cursor.execute(
                                "INSERT INTO login_history (nic, device_fingerprint, device_name, ip_address, " \
                                "location, suspicious) VALUES (%s, %s, %s, %s, %s, %s)",
                                (user[0], device_fingerprint, device_name, ip_address, location, False)
                            )
                            db.commit()
                        except Exception as e:
                            pass  # Log error in production
                        
                        flash('Welcome back! Logged in from trusted device.', 'success')
                        return redirect(url_for('index'))

                # --- Anomaly Detection for Non-Trusted Devices ---
                suspicious = False
                
                # Check for unknown device
                if device_fingerprint:
                    cursor.execute(
                        "SELECT COUNT(*) FROM user_devices WHERE nic = %s AND device_fingerprint = %s",
                        (user[0], device_fingerprint)
                    )
                    known_device = cursor.fetchone()[0] > 0
                    if not known_device:
                        suspicious = True
                
                # Check for new country (location)
                country = (location or '').split(',')[-1].strip() if location else ''
                cursor.execute(
                    "SELECT COUNT(*) FROM login_history WHERE nic = %s AND location LIKE %s",
                    (user[0], f"%{country}%")
                )
                known_country = cursor.fetchone()[0] > 0
                if not known_country:
                    suspicious = True

                # Record login history (with suspicious flag)
                try:
                    cursor.execute(
                        "INSERT INTO login_history (nic, device_fingerprint, device_name, ip_address, " \
                        "location, suspicious) VALUES (%s, %s, %s, %s, %s, %s)",
                        (user[0], device_fingerprint, device_name, ip_address, location, suspicious)
                    )
                    db.commit()
                except Exception as e:
                    pass  # Log error in production

                # Require TOTP for untrusted devices
                if suspicious:
                    flash('Suspicious login detected! Additional authentication required.', 'warning')
                else:
                    flash('Please complete two-factor authentication.', 'info')
                
                if device_fingerprint:
                    session['pending_fingerprint'] = device_fingerprint
                    session['pending_device_name'] = device_name
                
                # Redirect to verification choice page
                return redirect(url_for('choose_verification'))

                # --- End Anomaly Detection ---
            else:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('page-login.html')


# Route for Sign-Up Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        nic = request.form.get('nic')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        # Hash the password for security
        password_hash = generate_password_hash(password)
        secret_key = pyotp.random_base32()  # Generate a random secret key for TOTP

        # Check if user already exists
        ensure_db_connection()
        try:
            cursor.execute("SELECT nic, email, phone FROM users WHERE nic = %s OR email = %s OR phone = %s", (nic, email, phone))
            existing_user = cursor.fetchone()
            if existing_user:
                if existing_user[0] == nic:
                    flash('NIC already exists.', 'danger')
                elif existing_user[1] == email:
                    flash('Email already exists.', 'danger')
                elif existing_user[2] == phone:
                    flash('Phone number already exists.', 'danger')
                return redirect(url_for('signup'))
        except pymysql.MySQLError as err:
            flash(f'Database Error: {err}', 'danger')
            return redirect(url_for('signup'))

        # Prepare user data for email verification
        user_data = {
            'nic': nic,
            'full_name': full_name,
            'dob': dob,
            'gender': gender,
            'email': email,
            'phone': phone,
            'address': address,
            'password_hash': password_hash,
            'secret_key': secret_key
        }

        # Generate verification code and expiry time
        verification_code = generate_verification_code()
        expires_at = datetime.now() + timedelta(minutes=10)  # 10 minutes expiry

        try:
            # Clean up any existing verification codes for this email
            cursor.execute("DELETE FROM signup_email_verification WHERE email = %s", (email,))
            
            # Store verification data
            cursor.execute(
                "INSERT INTO signup_email_verification (email, verification_code, user_data, expires_at) VALUES (%s, %s, %s, %s)",
                (email, verification_code, json.dumps(user_data), expires_at)
            )
            db.commit()

            # Send verification email
            if send_signup_verification_email(email, verification_code, full_name):
                session['signup_email'] = email
                if EMAIL_ENABLED:
                    flash(f'Verification code sent to {email}! Please check your inbox and spam folder.', 'info')
                else:
                    flash(f'Email simulation mode: Check console for verification code. Code: {verification_code}', 'warning')
                return redirect(url_for('verify_signup_email'))
            else:
                if EMAIL_ENABLED:
                    flash(f'Error sending verification email to {email}. Please check email configuration.', 'danger')
                else:
                    flash(f'Email functionality is disabled. Code: {verification_code}', 'warning')
                    return redirect(url_for('verify_signup_email'))
                
        except pymysql.MySQLError as err:
            flash(f'Database Error: {err}', 'danger')
            return redirect(url_for('signup'))

    return render_template('page-sign-up.html')

    return render_template('page-sign-up.html')

# Route for Signup Email Verification
@app.route('/verify_signup_email', methods=['GET', 'POST'])
def verify_signup_email():
    email = session.get('signup_email')
    if not email:
        flash('Invalid verification session. Please sign up again.', 'danger')
        return redirect(url_for('signup'))
    
    if request.method == 'POST':
        if 'resend' in request.form:
            # Resend verification code
            ensure_db_connection()
            try:
                # Get the latest verification data for this email
                cursor.execute(
                    "SELECT user_data FROM signup_email_verification WHERE email = %s AND used = 0 ORDER BY created_at DESC LIMIT 1",
                    (email,)
                )
                result = cursor.fetchone()
                
                if result:
                    user_data = json.loads(result[0])
                    
                    # Generate new verification code
                    verification_code = generate_verification_code()
                    expires_at = datetime.now() + timedelta(minutes=10)
                    
                    # Update the verification code
                    cursor.execute(
                        "UPDATE signup_email_verification SET verification_code = %s, expires_at = %s, created_at = NOW() WHERE email = %s AND used = 0",
                        (verification_code, expires_at, email)
                    )
                    db.commit()
                    
                    # Send new verification email
                    if send_signup_verification_email(email, verification_code, user_data['full_name']):
                        if EMAIL_ENABLED:
                            flash(f'New verification code sent to {email}!', 'info')
                        else:
                            flash(f'Email simulation mode: New code: {verification_code}', 'warning')
                    else:
                        if EMAIL_ENABLED:
                            flash('Error sending verification email. Please try again.', 'danger')
                        else:
                            flash(f'Email disabled. New code: {verification_code}', 'warning')
                else:
                    flash('Verification session expired. Please sign up again.', 'danger')
                    session.pop('signup_email', None)
                    return redirect(url_for('signup'))
                    
            except pymysql.MySQLError as err:
                flash(f'Database Error: {err}', 'danger')
                return redirect(url_for('signup'))
            
            return render_template('verify_signup_email.html', email=email)
        
        # Verify the code
        entered_code = request.form.get('verification_code')
        
        if not entered_code:
            flash('Please enter the verification code.', 'danger')
            return render_template('verify_signup_email.html', email=email)
        
        ensure_db_connection()
        try:
            # Get verification data
            cursor.execute(
                "SELECT verification_code, user_data, expires_at FROM signup_email_verification WHERE email = %s AND used = 0 ORDER BY created_at DESC LIMIT 1",
                (email,)
            )
            result = cursor.fetchone()
            
            if not result:
                flash('Verification code expired or not found. Please sign up again.', 'danger')
                session.pop('signup_email', None)
                return redirect(url_for('signup'))
            
            stored_code, user_data_json, expires_at = result
            
            # Check if code is expired
            if datetime.now() > expires_at:
                flash('Verification code expired. Please request a new one.', 'danger')
                return render_template('verify_signup_email.html', email=email)
            
            # Verify the code
            if entered_code == stored_code:
                # Code is correct, create the user account
                user_data = json.loads(user_data_json)
                
                try:
                    # Insert user data into users table
                    query = """
                        INSERT INTO users (nic, full_name, dob, gender, email, phone, address, password_hash, secret_key, email_verified)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
                    """
                    cursor.execute(query, (
                        user_data['nic'], user_data['full_name'], user_data['dob'], 
                        user_data['gender'], user_data['email'], user_data['phone'], 
                        user_data['address'], user_data['password_hash'], user_data['secret_key']
                    ))
                    
                    # Mark verification as used
                    cursor.execute(
                        "UPDATE signup_email_verification SET used = 1 WHERE email = %s",
                        (email,)
                    )
                    
                    db.commit()
                    
                    # Clean up session
                    session.pop('signup_email', None)
                    
                    flash('Account created successfully! Email verified. You can now log in.', 'success')
                    return redirect(url_for('login'))
                    
                except pymysql.IntegrityError:
                    flash('Account with this information already exists. Please log in instead.', 'danger')
                    session.pop('signup_email', None)
                    return redirect(url_for('login'))
                except pymysql.MySQLError as err:
                    flash(f'Database Error: {err}', 'danger')
                    return redirect(url_for('signup'))
            else:
                flash('Invalid verification code. Please try again.', 'danger')
                
        except pymysql.MySQLError as err:
            flash(f'Database Error: {err}', 'danger')
            return redirect(url_for('signup'))
    
    return render_template('verify_signup_email.html', email=email)

    return render_template('verify_signup_email.html', email=email)

# Cleanup function for expired verification codes (call this periodically)
def cleanup_expired_verification_codes():
    """Clean up expired signup verification codes"""
    try:
        ensure_db_connection()
        cursor.execute("DELETE FROM signup_email_verification WHERE expires_at < NOW() AND used = 0")
        db.commit()
    except:
        pass  # Ignore errors in cleanup

        pass  # Ignore errors in cleanup

# Route for resending signup verification email
@app.route('/resend_signup_verification', methods=['GET', 'POST'])
def resend_signup_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Please enter your email address.', 'danger')
            return render_template('resend_signup_verification.html')
        
        ensure_db_connection()
        try:
            # Check if there's a pending verification for this email
            cursor.execute(
                "SELECT user_data FROM signup_email_verification WHERE email = %s AND used = 0 ORDER BY created_at DESC LIMIT 1",
                (email,)
            )
            result = cursor.fetchone()
            
            if result:
                user_data = json.loads(result[0])
                
                # Generate new verification code
                verification_code = generate_verification_code()
                expires_at = datetime.now() + timedelta(minutes=10)
                
                # Update the verification code
                cursor.execute(
                    "UPDATE signup_email_verification SET verification_code = %s, expires_at = %s, created_at = NOW() WHERE email = %s AND used = 0",
                    (verification_code, expires_at, email)
                )
                db.commit()
                
                # Send verification email
                if send_signup_verification_email(email, verification_code, user_data['full_name']):
                    session['signup_email'] = email
                    if EMAIL_ENABLED:
                        flash(f'Verification code sent to {email}!', 'info')
                    else:
                        flash(f'Email simulation mode: Code: {verification_code}', 'warning')
                    return redirect(url_for('verify_signup_email'))
                else:
                    if EMAIL_ENABLED:
                        flash('Error sending verification email. Please try again.', 'danger')
                    else:
                        flash(f'Email disabled. Code: {verification_code}', 'warning')
                        session['signup_email'] = email
                        return redirect(url_for('verify_signup_email'))
            else:
                # Check if user already exists and is verified
                cursor.execute("SELECT email_verified FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
                
                if user:
                    if user[0]:  # email_verified is True
                        flash('This email is already verified. You can log in.', 'info')
                        return redirect(url_for('login'))
                    else:
                        flash('Account exists but email not verified. Please contact support.', 'warning')
                        return redirect(url_for('login'))
                else:
                    flash('No pending verification found for this email. Please sign up first.', 'warning')
                    return redirect(url_for('signup'))
                    
        except pymysql.MySQLError as err:
            flash(f'Database Error: {err}', 'danger')
    
    return render_template('resend_signup_verification.html')

# Route for choosing verification method
@app.route('/choose_verification')
def choose_verification():
    nic = session.get('nic')
    if not nic:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('choose_verification.html')

# Route for email verification
@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    nic = session.get('nic')
    if not nic:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    # Get user data
    cursor.execute("SELECT full_name, email FROM users WHERE nic = %s", (nic,))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    user_name, email = user
    
    if request.method == 'POST':
        entered_code = request.form.get('verification_code')
        trust_device = request.form.get('trust_device')
        device_fingerprint = request.form.get('device_fingerprint') or session.get('pending_fingerprint')
        device_name = request.form.get('device_name') or session.get('pending_device_name')
        
        stored_code = session.get('email_verification_code')
        code_timestamp = session.get('email_code_timestamp')
        
        if not stored_code or not code_timestamp:
            flash('Verification code expired. Please request a new one.', 'danger')
            return redirect(url_for('verify_email'))
        
        # Check if code is expired (1 minute)
        if (datetime.now().timestamp() - code_timestamp) > 60:  # 1 minute
            session.pop('email_verification_code', None)
            session.pop('email_code_timestamp', None)
            flash('Verification code expired. Please request a new one.', 'danger')
            return redirect(url_for('verify_email'))
        
        if entered_code == stored_code:
            # Code is correct
            session.pop('email_verification_code', None)
            session.pop('email_code_timestamp', None)
            
            # If user wants to trust this device, store in DB
            if trust_device and device_fingerprint:
                try:
                    cursor.execute(
                        "INSERT INTO user_devices (nic, device_fingerprint, device_name, trusted, last_used) VALUES (%s, %s, %s, 1, NOW()) "
                        "ON DUPLICATE KEY UPDATE trusted=1, last_used=NOW(), device_name=%s",
                        (nic, device_fingerprint, device_name, device_name)
                    )
                    db.commit()
                    flash('Email verified successfully! Device has been marked as trusted.', 'success')
                except Exception as e:
                    pass  # Log error in production
                    flash('Email verified successfully! Feel Free to Explore!', 'success')
            else:
                flash('Email verified successfully! Feel Free to Explore!', 'success')
            
            # Clear pending session data
            session.pop('pending_fingerprint', None)
            session.pop('pending_device_name', None)
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    # Generate and send verification code
    if request.method == 'GET' or 'resend' in request.form:
        verification_code = generate_verification_code()
        if send_verification_email(email, verification_code, user_name):
            session['email_verification_code'] = verification_code
            session['email_code_timestamp'] = datetime.now().timestamp()
            if EMAIL_ENABLED:
                flash(f'Verification code sent to {email}! Check your inbox and spam folder.', 'info')
            else:
                flash(f'Email simulation mode: Check console for verification code. Code: {verification_code}', 'warning')
        else:
            if EMAIL_ENABLED:
                flash(f'Error sending verification email to {email}. Please check email configuration.', 'danger')
            else:
                flash('Email functionality is disabled. Check console for verification code.', 'warning')
            # Don't redirect back to choose_verification if email is disabled for testing
            if EMAIL_ENABLED:
                return redirect(url_for('choose_verification'))
    
    return render_template('verify_email.html', email=email)

# Log Out
@app.route('/logout')
def logout():
    session.pop('nic', None)  # Ensure NIC is removed from session on logout
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))

# Route for QR Code Verification
@app.route('/verify_qr_totp', methods=['GET', 'POST'])
def verify_qr_totp():
    nic = session.get('nic')  # Retrieve NIC from session

    if not nic:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    # Fetch secret_key using NIC
    cursor.execute("SELECT secret_key FROM users WHERE nic = %s", (nic,))
    user = cursor.fetchone()

    if user:
        secret_key = user[0]
        issuer_name = "Arogya"
        provisioning_uri = pyotp.TOTP(secret_key).provisioning_uri(name=nic, issuer_name=issuer_name)

        qr = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        if request.method == 'POST':
            otp = request.form.get('otp')
            trust_device = request.form.get('trust_device')
            device_fingerprint = request.form.get('device_fingerprint') or session.pop('pending_fingerprint', None)
            device_name = request.form.get('device_name') or session.pop('pending_device_name', None)
            totp = pyotp.TOTP(secret_key)
            if totp.verify(otp):
                # If user wants to trust this device, store in DB
                if trust_device and device_fingerprint:
                    try:
                        cursor.execute(
                            "INSERT INTO user_devices (nic, device_fingerprint, device_name, trusted, last_used) VALUES (%s, %s, %s, 1, NOW()) "
                            "ON DUPLICATE KEY UPDATE trusted=1, last_used=NOW(), device_name=%s",
                            (nic, device_fingerprint, device_name, device_name)
                        )
                        db.commit()
                        flash('OTP verified successfully! Device has been marked as trusted.', 'success')
                    except Exception as e:
                        pass  # Log error in production
                        flash('OTP verified successfully! Feel Free to Explore!', 'success')
                else:
                    flash('OTP verified successfully! Feel Free to Explore!', 'success')
                
                # Clear any pending session data
                session.pop('pending_fingerprint', None)
                session.pop('pending_device_name', None)
                return redirect(url_for('index'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')

        return render_template('verify_qr_totp.html', qr_code=qr_code_base64)

    flash('Error generating QR code.', 'danger')
    return redirect(url_for('login'))

@app.route('/security_dashboard', methods=['GET', 'POST'])
def security_dashboard():
    nic = session.get('nic')
    if not nic:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'revoke_device':
            # Revoke (delete) a device
            device_id = request.form.get('device_id')
            if device_id:
                try:
                    cursor.execute("DELETE FROM user_devices WHERE id = %s AND nic = %s", (device_id, nic))
                    db.commit()
                    flash('Device revoked successfully. This device will need to authenticate again.', 'success')
                except Exception as e:
                    flash(f'Error revoking device: {e}', 'danger')
        
        return redirect(url_for('security_dashboard'))

    # Get trusted devices for this user
    cursor.execute("SELECT id, device_fingerprint, device_name, last_used, trusted FROM user_devices WHERE nic = %s ORDER BY last_used DESC", (nic,))
    devices = cursor.fetchall()
    
    # Get login history for this user
    cursor.execute("SELECT device_name, ip_address, location, login_time, suspicious FROM login_history WHERE nic = %s ORDER BY login_time DESC LIMIT 50", (nic,))
    history = cursor.fetchall()
    
    # Count suspicious activities
    cursor.execute("SELECT COUNT(*) FROM login_history WHERE nic = %s AND suspicious = 1", (nic,))
    suspicious_result = cursor.fetchone()
    suspicious_count = suspicious_result[0] if suspicious_result else 0
    
    return render_template('security_dashboard.html', devices=devices, history=history, suspicious_count=suspicious_count)

@app.route('/trusted_devices', methods=['GET', 'POST'])
def trusted_devices():
    # Redirect to the new unified dashboard
    return redirect(url_for('security_dashboard'))

@app.route('/login_history')
def login_history():
    # Redirect to the new unified dashboard
    return redirect(url_for('security_dashboard'))

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/blog-single')
def blog_single():
    return render_template('blog-single.html')

@app.route('/page-404')
def page_404():
    return render_template('page-404.html')

@app.route('/page-about')
def page_about():
    return render_template('page-about.html')

@app.route('/page-contact-us')
def page_contact_us():
    return render_template('page-contact-us.html')

@app.route('/doctor-layout')
def doctor_layout():
    return render_template('doctor-layout.html')

@app.route('/single-listings')
def single_listings():
    return render_template('single-listings.html')

@app.route('/dashboard-add-listing')
def dashboard_add_listing():
    return render_template('dashboard-add-listing.html')

@app.route('/dashboard-bookings')
def dashboard_bookings():
    return render_template('dashboard-bookings.html')

@app.route('/dashboard-home')
def dashboard_home():
    return render_template('dashboard-home.html')

@app.route('/dashboard-my-favorites')
def dashboard_my_favorites():
    return render_template('dashboard-my-favorites.html')

@app.route('/dashboard-my-listings')
def dashboard_my_listings():
    return render_template('dashboard-my-listings.html')

@app.route('/dashboard-my-profile', methods=['GET', 'POST'])
def dashboard_my_profile():
    nic = session.get('nic')
    if not nic:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle profile update
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        address = request.form.get('address')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        try:
            # Update basic profile information
            cursor.execute("""
                UPDATE users 
                SET full_name = %s, email = %s, phone = %s, dob = %s, gender = %s, address = %s
                WHERE nic = %s
            """, (full_name, email, phone, dob, gender, address, nic))
            
            # Handle password update if provided
            if new_password:
                if new_password != confirm_password:
                    flash('Passwords do not match.', 'danger')
                    return redirect(url_for('dashboard_my_profile'))
                
                password_hash = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password_hash = %s WHERE nic = %s", (password_hash, nic))
            
            db.commit()
            flash('Profile updated successfully!', 'success')
            
        except pymysql.IntegrityError:
            flash('Email or phone number already exists.', 'danger')
        except pymysql.MySQLError as err:
            flash(f'Database Error: {err}', 'danger')
            
        return redirect(url_for('dashboard_my_profile'))
    
    # Fetch user data for display
    cursor.execute("SELECT nic, full_name, dob, gender, email, phone, address FROM users WHERE nic = %s", (nic,))
    user_data = cursor.fetchone()
    
    if user_data:
        user_dict = {
            'nic': user_data[0],
            'full_name': user_data[1],
            'dob': user_data[2],
            'gender': user_data[3],
            'email': user_data[4],
            'phone': user_data[5],
            'address': user_data[6]
        }
        user_name = user_data[1]  # full_name for header display
    else:
        user_dict = None
        user_name = 'User'
    
    return render_template('dashboard-my-profile.html', user_data=user_dict, user_name=user_name)

@app.route('/dashboard-packages')
def dashboard_packages():
    return render_template('dashboard-packages.html')

@app.route('/dashboard-reviews')
def dashboard_reviews():
    return render_template('dashboard-reviews.html')

@app.route('/map-grid-layout')
def map_grid_layout():
    return render_template('map-grid-layout.html')

@app.route('/map-list-layout')
def map_list_layout():
    return render_template('map-list-layout.html')

@app.route('/page-pricing-tables')
def page_pricing_tables():
    return render_template('page-pricing-tables.html')

# Start Flask server
if __name__ == '__main__':
    try:
        # Clean up expired verification codes on startup
        cleanup_expired_verification_codes()
        print("Arogya Healthcare System Starting...")
        print("Database connected successfully...")
        print("Security features activated successfully...")
        app.run(debug=True, port=5000, host='127.0.0.1', threaded=True)
    except Exception as e:
        print(f"Error starting server: {e}")
        pass
