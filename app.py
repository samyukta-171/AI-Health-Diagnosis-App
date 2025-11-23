import os
import re
import time
import json
import bcrypt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from werkzeug.utils import secure_filename
from groq import Groq

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "mysql+pymysql://root:_samyukta_@localhost/healthcare_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB uploads
app.config["JWT_VERIFY_SUB"] = False  # Fix for PyJWT >=2.10.0 bug

# Allow all localhost origins for development
CORS(app, 
     resources={r"/*": {"origins": "*"}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Groq AI client (use environment variable for API key)
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # <-- Fixed here

    def set_password(self, password: str):
        """Hash password using bcrypt"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False


class Patient(db.Model):
    __tablename__ = "patient"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.String(10), nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    blood_type = db.Column(db.String(10), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    mobile = db.Column(db.String(20), nullable=True)
    profile_photo_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship("User", backref=db.backref("patient", uselist=False))


class DiagnosisRecord(db.Model):
    __tablename__ = "diagnosis_record"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    disease_name = db.Column(db.String(255), nullable=False)
    symptoms_json = db.Column(db.Text, nullable=False)
    diagnosis_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship("Patient", backref=db.backref("diagnosis_records", lazy=True))


class LabReportRecord(db.Model):
    __tablename__ = "lab_report_record"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    report_type = db.Column(db.String(255), nullable=False)
    analysis_text = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship("Patient", backref=db.backref("lab_reports", lazy=True))


class PrescriptionRecord(db.Model):
    __tablename__ = "prescription_record"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    medication_name = db.Column(db.String(255), nullable=False)
    analysis_text = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship("Patient", backref=db.backref("prescriptions", lazy=True))


def is_valid_date_string(s):
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except Exception:
        return False


def is_strong_password(pw: str):
    if not pw or len(pw) < 6:
        return False, "Password must be at least 6 characters."
    if not re.search(r"[A-Za-z]", pw):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", pw):
        return False, "Password must contain at least one number."
    return True, ""


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Auth & Patient backend running"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if role not in ("patient", "doctor"):
        return jsonify({"error": "role_required"}), 400
    if not username:
        return jsonify({"error": "username_required"}), 400
    if not password:
        return jsonify({"error": "password_required"}), 400
    ok, msg = is_strong_password(password)
    if not ok:
        return jsonify({"error": "weak_password", "message": msg}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "user_exists"}), 409
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "credentials_required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "invalid_credentials"}), 401

    identity = str(user.id)
    additional_claims = {"username": user.username, "role": user.role}
    token = create_access_token(identity=identity, additional_claims=additional_claims)
    return jsonify({"token": token, "role": user.role, "message": "Login successful!"}), 200


@app.route("/patient", methods=["POST"])
@jwt_required()
def create_patient():
    jwt_claims = get_jwt()
    role = jwt_claims.get("role")
    if role != "patient":
        return jsonify({"error": "forbidden", "message": "Only patients can create profile"}), 403

    user_id_str = get_jwt_identity()
    try:
        user_id = int(user_id_str)
    except Exception:
        return jsonify({"error": "invalid_identity"}), 401

    if Patient.query.filter_by(user_id=user_id).first():
        return jsonify({"error": "exists", "message": "Patient profile already exists"}), 409

    data = request.get_json(silent=True) or {}
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    dob = data.get("date_of_birth")
    gender = (data.get("gender") or "").strip()
    blood_type = (data.get("blood_type") or "").strip()
    email = (data.get("email") or "").strip()
    mobile = (data.get("mobile") or "").strip()
    profile_photo_url = data.get("profile_photo_url")
    if not first_name or not last_name or not dob or not gender:
        return jsonify({"error": "missing_fields", "message": "first_name, last_name, date_of_birth and gender required"}), 400
    if not is_valid_date_string(dob):
        return jsonify({"error": "invalid_date", "message": "date_of_birth must be YYYY-MM-DD"}), 400

    p = Patient(
        user_id=user_id,
        first_name=first_name,
        last_name=last_name,
        date_of_birth=dob,
        gender=gender,
        blood_type=blood_type or None,
        email=email or None,
        mobile=mobile or None,
        profile_photo_url=profile_photo_url
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({"message": "Patient profile created", "id": p.id}), 201


@app.route("/patient/me", methods=["GET"])
@jwt_required()
def get_my_patient():
    jwt_claims = get_jwt()
    role = jwt_claims.get("role")
    if role != "patient":
        return jsonify({"error": "forbidden"}), 403

    user_id_str = get_jwt_identity()
    try:
        user_id = int(user_id_str)
    except Exception:
        return jsonify({"error": "invalid_identity"}), 401

    p = Patient.query.filter_by(user_id=user_id).first()
    if not p:
        return jsonify({"message": "No profile"}), 404

    # Calculate age from date_of_birth
    age = None
    if p.date_of_birth:
        try:
            from datetime import datetime
            dob = datetime.strptime(p.date_of_birth, "%Y-%m-%d")
            today = datetime.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        except:
            age = None

    return jsonify({
        "id": p.id,
        "user_id": p.user_id,
        "first_name": p.first_name,
        "last_name": p.last_name,
        "date_of_birth": p.date_of_birth,
        "age": age,
        "email": p.email,
        "mobile": p.mobile,
        "contact": p.mobile,  # alias for mobile
        "gender": p.gender,
        "blood_type": p.blood_type or "Not Set",
        "profile_photo_url": p.profile_photo_url
    }), 200


@app.route("/patient/me", methods=["PUT"])
@jwt_required()
def update_my_patient():
    jwt_claims = get_jwt()
    role = jwt_claims.get("role")
    if role != "patient":
        return jsonify({"error": "forbidden"}), 403

    user_id_str = get_jwt_identity()
    try:
        user_id = int(user_id_str)
    except Exception:
        return jsonify({"error": "invalid_identity"}), 401

    p = Patient.query.filter_by(user_id=user_id).first()
    if not p:
        return jsonify({"message": "No profile to update"}), 404

    data = request.get_json(silent=True) or {}
    if "first_name" in data:
        p.first_name = (data.get("first_name") or p.first_name).strip()
    if "last_name" in data:
        p.last_name = (data.get("last_name") or p.last_name).strip()
    if "date_of_birth" in data:
        dob = data.get("date_of_birth")
        if dob:
            if not is_valid_date_string(dob):
                return jsonify({"error": "invalid_date"}), 400
            p.date_of_birth = dob
    if "gender" in data:
        p.gender = (data.get("gender") or p.gender).strip()
    if "blood_type" in data:
        p.blood_type = (data.get("blood_type") or "").strip() or None
    if "email" in data:
        p.email = (data.get("email") or p.email).strip()
    if "mobile" in data:
        p.mobile = (data.get("mobile") or p.mobile).strip()
    if "profile_photo_url" in data:
        p.profile_photo_url = data.get("profile_photo_url")
    db.session.commit()
    return jsonify({"message": "Profile updated"}), 200


@app.route("/patient/history", methods=["GET"])
@jwt_required()
def patient_history():
    """Get patient's complete medical history including all diagnoses"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a patient (case-insensitive)
    if user.role.lower() != "patient":
        return jsonify({"error": "unauthorized"}), 403

    patient = Patient.query.filter_by(user_id=current_user_id).first()
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404

    # Get all diagnosis records for this patient
    diagnosis_records = DiagnosisRecord.query.filter_by(patient_id=patient.id).all()
    lab_report_records = LabReportRecord.query.filter_by(patient_id=patient.id).all()
    prescription_records = PrescriptionRecord.query.filter_by(patient_id=patient.id).all()

    print(f"Patient ID: {patient.id}")
    print(f"Diagnosis records: {len(diagnosis_records)}")
    print(f"Lab report records: {len(lab_report_records)}")
    print(f"Prescription records: {len(prescription_records)}")

    history = []
    
    # Add symptom diagnosis records
    for record in diagnosis_records:
        history.append({
            "id": f"symptom_{record.id}",
            "type": "symptom",
            "disease_name": record.disease_name,
            "symptoms_json": record.symptoms_json,
            "diagnosis_text": record.diagnosis_text,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at  # For sorting
        })
    
    # Add lab report records
    for record in lab_report_records:
        history.append({
            "id": f"lab_{record.id}",
            "type": "lab_report",
            "report_type": record.report_type,
            "analysis_text": record.analysis_text,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at  # For sorting
        })
    
    # Add prescription records
    for record in prescription_records:
        history.append({
            "id": f"prescription_{record.id}",
            "type": "prescription",
            "medication_name": record.medication_name,
            "analysis_text": record.analysis_text,
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at  # For sorting
        })
    
    # Sort all records by created_at in descending order
    history.sort(key=lambda x: x["created_at_raw"] if x["created_at_raw"] else datetime.min, reverse=True)
    
    # Remove the temporary sorting field
    for record in history:
        del record["created_at_raw"]

    return jsonify({
        "records": history,
        "total": len(history)
    }), 200


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

def allowed_filename(filename):
    return "." in filename and filename.rsplit(".", 1)[-1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload-photo", methods=["POST"])
def upload_photo():
    try:
        token_in_form = request.form.get("token")
    except Exception:
        token_in_form = None

    if token_in_form and not request.headers.get("Authorization"):
        request.environ["HTTP_AUTHORIZATION"] = f"Bearer {token_in_form}"

    try:
        verify_jwt_in_request()
    except Exception as e:
        return jsonify({"error": "invalid_token", "message": str(e)}), 401

    user_id_str = get_jwt_identity()
    try:
        user_id = int(user_id_str)
    except Exception:
        return jsonify({"error": "invalid_identity"}), 401

    if "photo" not in request.files:
        return jsonify({"error": "no_file", "message": "No file part named 'photo' in request"}), 400

    f = request.files["photo"]
    if f.filename == "":
        return jsonify({"error": "empty_filename", "message": "Empty filename"}), 400

    filename = secure_filename(f.filename)
    if not allowed_filename(filename):
        return jsonify({"error": "invalid_file_type", "message": "Allowed: png/jpg/jpeg/gif/webp"}), 400

    ext = filename.rsplit(".", 1)[-1].lower()
    new_name = f"user_{user_id}_{int(time.time())}.{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, new_name)
    try:
        f.save(save_path)
    except Exception as e:
        app.logger.exception("Failed to save upload")
        return jsonify({"error": "save_failed", "message": str(e)}), 500

    url_path = f"/uploads/{new_name}"
    try:
        p = Patient.query.filter_by(user_id=user_id).first()
        if p:
            p.profile_photo_url = url_path
            db.session.commit()
    except Exception:
        app.logger.exception("Failed to attach profile image to patient")

    full_url = request.host_url.rstrip("/") + url_path
    return jsonify({"url": full_url}), 201

@app.route("/uploads/<path:filename>", methods=["GET"])
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/diagnosis", methods=["POST"])
@jwt_required()
def create_diagnosis():
    user_id_str = get_jwt_identity()
    user_id = int(user_id_str)
    patient = Patient.query.filter_by(user_id=user_id).first()
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404

    data = request.get_json() or {}
    disease = data.get("disease")
    symptoms = data.get("symptoms")
    if not disease or not symptoms:
        return jsonify({"error": "missing_parameters"}), 400

    symptom_list_text = ", ".join(symptoms)
    prompt = (
        f"Given these symptoms: {symptom_list_text} for disease {disease}, "
        "provide a professional medical diagnosis, possible differential diagnoses, "
        "and recommendations in clear, formal medical language."
    )

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.6
        )
        diagnosis_text = response.choices[0].message.content.strip()
    except Exception as e:
        return jsonify({"error": "groq_error", "message": str(e)}), 500

    record = DiagnosisRecord(
        patient_id=patient.id,
        disease_name=disease,
        symptoms_json=json.dumps(symptoms),
        diagnosis_text=diagnosis_text
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "diagnosis": diagnosis_text,
        "message": "Diagnosis created and saved."
    }), 201


@app.route("/analyze-report", methods=["POST"])
@jwt_required()
def analyze_report():
    """Analyze uploaded medical report"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a patient (case-insensitive)
    if user.role.lower() != "patient":
        return jsonify({"error": "unauthorized", "role": user.role}), 403

    patient = Patient.query.filter_by(user_id=current_user_id).first()
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404

    # Get report type from form data (not JSON)
    report_type = request.form.get("reportType", "")
    
    if not report_type:
        return jsonify({"error": "missing_report_type"}), 400

    # Create AI prompt based on report type with recovery information
    prompts = {
        "X-Ray - Heel/Foot": """Analyze a heel/foot X-ray report. Provide:
1. **Common Findings**: Describe potential issues like fractures, bone spurs, arthritis
2. **Medical Recommendations**: Treatment options and care instructions
3. **Recovery Percentage**: Estimate cure rate (e.g., 85-95% with proper treatment)
4. **Recovery Timeline**: Expected healing time (e.g., 4-6 weeks for minor fractures)""",
        
        "X-Ray - Chest": """Analyze a chest X-ray report. Provide:
1. **Common Findings**: Pneumonia, tuberculosis, lung nodules, heart enlargement
2. **Medical Recommendations**: Treatment and follow-up care
3. **Recovery Percentage**: Expected cure rate based on condition severity
4. **Recovery Timeline**: Typical recovery duration""",
        
        "Blood Test - Complete": """Analyze a Complete Blood Count (CBC) test. Provide:
1. **Test Parameters**: Explain RBC, WBC, platelets, hemoglobin levels
2. **Abnormality Indicators**: What high/low values suggest
3. **Recovery Percentage**: Cure rate for identified conditions (e.g., 90% for anemia with treatment)
4. **Recovery Timeline**: Expected time to normalize levels""",
        
        "Blood Test - Sugar": """Analyze blood glucose/diabetes test. Provide:
1. **Test Results**: Explain fasting sugar, HbA1c levels
2. **Diabetes Indicators**: Pre-diabetic or diabetic ranges
3. **Recovery Percentage**: Control rate with lifestyle changes and medication
4. **Recovery Timeline**: Time to achieve normal glucose levels""",
        
        "Blood Test - Liver": """Analyze Liver Function Test (LFT). Provide:
1. **Liver Enzymes**: ALT, AST, bilirubin interpretation
2. **Health Indicators**: What levels indicate about liver condition
3. **Recovery Percentage**: Healing rate based on cause (e.g., 80-90% for fatty liver)
4. **Recovery Timeline**: Expected recovery duration with treatment""",
        
        "Blood Test - Kidney": """Analyze Kidney Function Test. Provide:
1. **Kidney Markers**: Creatinine, BUN, GFR levels
2. **Health Status**: Kidney function assessment
3. **Recovery Percentage**: Improvement rate with treatment
4. **Recovery Timeline**: Expected time for kidney function restoration""",
        
        "Blood Test - Thyroid": """Analyze Thyroid Function Test. Provide:
1. **Thyroid Hormones**: TSH, T3, T4 level interpretation
2. **Health Assessment**: Hypo/hyperthyroid indicators
3. **Recovery Percentage**: Control rate with medication (typically 95%+)
4. **Recovery Timeline**: Time to normalize thyroid levels""",
        
        "Urine Test": """Analyze urine test report. Provide:
1. **Test Findings**: Infection indicators, kidney function markers
2. **Health Implications**: What abnormalities suggest
3. **Recovery Percentage**: Cure rate for infections (90-95% with antibiotics)
4. **Recovery Timeline**: Treatment duration (typically 3-7 days)""",
        
        "ECG/EKG": """Analyze ECG/EKG report. Provide:
1. **Heart Rhythm**: Rate and rhythm analysis
2. **Abnormalities**: Potential cardiac issues detected
3. **Recovery Percentage**: Success rate of treatment based on findings
4. **Recovery Timeline**: Expected recovery or management timeline""",
        
        "MRI Scan": """Analyze MRI scan report. Provide:
1. **Imaging Findings**: Soft tissue abnormalities detected
2. **Medical Implications**: Potential diagnoses
3. **Recovery Percentage**: Cure rate for identified conditions
4. **Recovery Timeline**: Expected healing or treatment duration""",
        
        "CT Scan": """Analyze CT scan report. Provide:
1. **Scan Results**: Cross-sectional imaging findings
2. **Medical Assessment**: Health implications
3. **Recovery Percentage**: Treatment success rate
4. **Recovery Timeline**: Expected recovery period""",
        
        "Ultrasound": """Analyze ultrasound report. Provide:
1. **Ultrasound Findings**: Organ/area scan results
2. **Health Evaluation**: Normal or abnormal findings
3. **Recovery Percentage**: Cure rate if issues detected
4. **Recovery Timeline**: Expected healing duration""",
        
        "Other": """Analyze this medical report. Provide:
1. **Key Findings**: Main results and observations
2. **Health Implications**: What the results indicate
3. **Recovery Percentage**: Expected cure/improvement rate
4. **Recovery Timeline**: Typical duration for recovery or management"""
    }

    prompt = prompts.get(report_type, prompts["Other"])

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.7
        )
        analysis = response.choices[0].message.content.strip()
        
        # Save lab report record to database
        lab_record = LabReportRecord(
            patient_id=patient.id,
            report_type=report_type,
            analysis_text=analysis
        )
        db.session.add(lab_record)
        db.session.commit()
        print(f"✅ Lab report saved for patient {patient.id}: {report_type}")
        
        return jsonify({
            "analysis": analysis,
            "reportType": report_type
        }), 200
    except Exception as e:
        return jsonify({"error": "groq_error", "message": str(e)}), 500


@app.route("/analyze-prescription", methods=["POST"])
@jwt_required()
def analyze_prescription():
    """Analyze uploaded prescription"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a patient (case-insensitive)
    if user.role.lower() != "patient":
        return jsonify({"error": "unauthorized", "role": user.role}), 403

    # Get medicine name from form data (frontend sends FormData)
    medicine_name = request.form.get("medicineName", "").strip()
    
    if not medicine_name:
        return jsonify({"error": "missing_medication"}), 400

    # Create detailed prompt for medicine information
    prompt = f"""Provide comprehensive information about the medication: {medicine_name}

Include the following details:
1. **Primary Use**: What condition(s) is this medication used to treat?
2. **Dosage Guidelines**: Typical dosage for adults and any special considerations
3. **How to Take**: Instructions on when and how to take this medication
4. **Side Effects**: Common and serious side effects to watch for
5. **Precautions**: Who should avoid this medication and important warnings
6. **Drug Interactions**: Important interactions with other medications or foods
7. **Storage**: How to properly store this medication

Provide the information in a clear, professional medical format."""

    patient = Patient.query.filter_by(user_id=current_user_id).first()
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.7
        )
        analysis = response.choices[0].message.content.strip()
        
        # Save prescription record to database
        prescription_record = PrescriptionRecord(
            patient_id=patient.id,
            medication_name=medicine_name,
            analysis_text=analysis
        )
        db.session.add(prescription_record)
        db.session.commit()
        print(f"✅ Prescription saved for patient {patient.id}: {medicine_name}")
        
        return jsonify({
            "analysis": analysis,
            "medication": medicine_name
        }), 200
    except Exception as e:
        return jsonify({"error": "groq_error", "message": str(e)}), 500


@app.route("/medical-consultation", methods=["POST"])
@jwt_required()
def medical_consultation():
    """Get AI medical consultation based on diagnosis history"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a patient (case-insensitive)
    if user.role.lower() != "patient":
        return jsonify({"error": "unauthorized", "role": user.role}), 403

    patient = Patient.query.filter_by(user_id=current_user_id).first()
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404

    # Get recent diagnoses
    records = DiagnosisRecord.query.filter_by(patient_id=patient.id).order_by(
        DiagnosisRecord.created_at.desc()
    ).limit(5).all()

    if not records:
        return jsonify({"error": "no_diagnosis_history"}), 404

    # Build consultation prompt
    history = []
    for record in records:
        history.append(f"Disease: {record.disease_name}, Diagnosis: {record.diagnosis_text[:200]}")
    
    history_text = "\n".join(history)
    prompt = f"""Based on this patient's recent medical history:

{history_text}

Provide:
1. Overall health summary
2. Recommended specialist doctor type
3. Urgency level (Low/Medium/High)
4. General health recommendations

Use professional medical language."""

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.7
        )
        consultation = response.choices[0].message.content.strip()
        
        return jsonify({
            "consultation": consultation,
            "diagnosisCount": len(records)
        }), 200
    except Exception as e:
        return jsonify({"error": "groq_error", "message": str(e)}), 500


# ==================== DOCTOR ENDPOINTS ====================

@app.route("/doctor/patients", methods=["GET"])
@jwt_required()
def get_all_patients():
    """Get list of all patients for doctor to view"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a doctor
    if user.role.lower() != "doctor":
        return jsonify({"error": "unauthorized"}), 403
    
    # Get all patients
    patients = Patient.query.all()
    
    patient_list = []
    for p in patients:
        # Calculate age
        age = None
        if p.date_of_birth:
            try:
                dob = datetime.strptime(p.date_of_birth, "%Y-%m-%d")
                today = datetime.today()
                age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            except:
                age = None
        
        # Count total medical records
        diagnosis_count = DiagnosisRecord.query.filter_by(patient_id=p.id).count()
        lab_count = LabReportRecord.query.filter_by(patient_id=p.id).count()
        prescription_count = PrescriptionRecord.query.filter_by(patient_id=p.id).count()
        total_records = diagnosis_count + lab_count + prescription_count
        
        patient_list.append({
            "id": p.id,
            "first_name": p.first_name,
            "last_name": p.last_name,
            "age": age,
            "gender": p.gender,
            "blood_type": p.blood_type or "Not Set",
            "mobile": p.mobile,
            "email": p.email,
            "total_records": total_records,
            "created_at": p.created_at.isoformat() if p.created_at else None
        })
    
    return jsonify({
        "patients": patient_list,
        "total": len(patient_list)
    }), 200


@app.route("/doctor/patient/<int:patient_id>/history", methods=["GET"])
@jwt_required()
def get_patient_history_for_doctor(patient_id):
    """Get complete medical history of a specific patient with FULL AI results"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if user is a doctor
    if user.role.lower() != "doctor":
        return jsonify({"error": "unauthorized"}), 403
    
    # Get patient
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({"error": "patient_not_found"}), 404
    
    # Calculate age
    age = None
    if patient.date_of_birth:
        try:
            dob = datetime.strptime(patient.date_of_birth, "%Y-%m-%d")
            today = datetime.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        except:
            age = None
    
    # Get patient info
    patient_info = {
        "id": patient.id,
        "first_name": patient.first_name,
        "last_name": patient.last_name,
        "age": age,
        "date_of_birth": patient.date_of_birth,
        "gender": patient.gender,
        "blood_type": patient.blood_type or "Not Set",
        "mobile": patient.mobile,
        "email": patient.email
    }
    
    # Get all medical records
    diagnosis_records = DiagnosisRecord.query.filter_by(patient_id=patient_id).all()
    lab_report_records = LabReportRecord.query.filter_by(patient_id=patient_id).all()
    prescription_records = PrescriptionRecord.query.filter_by(patient_id=patient_id).all()
    
    history = []
    
    # Add symptom diagnosis records (WITH full AI analysis)
    for record in diagnosis_records:
        history.append({
            "id": f"symptom_{record.id}",
            "type": "symptom",
            "disease_name": record.disease_name,
            "symptoms_json": record.symptoms_json,
            "diagnosis_text": record.diagnosis_text,  # FULL AI RESULT for doctor
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at
        })
    
    # Add lab report records (WITH full AI analysis)
    for record in lab_report_records:
        history.append({
            "id": f"lab_{record.id}",
            "type": "lab_report",
            "report_type": record.report_type,
            "analysis_text": record.analysis_text,  # FULL AI RESULT for doctor
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at
        })
    
    # Add prescription records (WITH full AI analysis)
    for record in prescription_records:
        history.append({
            "id": f"prescription_{record.id}",
            "type": "prescription",
            "medication_name": record.medication_name,
            "analysis_text": record.analysis_text,  # FULL AI RESULT for doctor
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "created_at_raw": record.created_at
        })
    
    # Sort by date descending
    history.sort(key=lambda x: x["created_at_raw"] if x["created_at_raw"] else datetime.min, reverse=True)
    
    # Remove temporary sorting field
    for record in history:
        del record["created_at_raw"]
    
    return jsonify({
        "patient": patient_info,
        "records": history,
        "total": len(history)
    }), 200


if __name__ == "__main__":
    AUTO = os.getenv("AUTO_CREATE_TABLES", "true").strip().lower() != "false"
    with app.app_context():
        if AUTO:
            try:
                db.create_all()
                print("DB tables created/checked.")
            except Exception as e:
                print("DB create_all() error:", e)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
