"""
Hospital Management System v3.0
Python Flask + SQLite
Complete End-to-End with:
  - Pharmacy: Medicine stock + Dispense to Patients + Purchase/Stock-In
  - Staff/User Management: Create users with roles + module access control
  - All modules fully functional end-to-end
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g, abort
import sqlite3, os, hashlib, json
from datetime import datetime, date, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'trinetra_hms_v3_2025'
DATABASE = os.path.join(os.path.dirname(__file__), 'hms.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def qdb(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def edb(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

def hash_pw(pw): return hashlib.md5(pw.encode()).hexdigest()

# ─────────────────────────────────────────────
# AUTH & PERMISSIONS
# ─────────────────────────────────────────────
ALL_MODULES = [
    'dashboard','patients','opd','ipd','beds','lab','pharmacy',
    'staff','payroll','hr_leave','hr_attendance','hr_appraisal','hr_training',
    'appointments','bloodbank','insurance','vehicle',
    'income','expenses','reports','admin'
]

def get_user(): return session.get('hospitaladmin', {})

def get_user_permissions():
    user = get_user()
    if not user: return {}
    if user.get('roles') == 'Super Admin':
        return {m: {'view':True,'add':True,'edit':True,'delete':True} for m in ALL_MODULES}
    role_id = user.get('role_id', 0)
    rows = qdb("SELECT module,can_view,can_add,can_edit,can_delete FROM role_permissions WHERE role_id=?", (role_id,))
    return {r['module']: {'view':bool(r['can_view']),'add':bool(r['can_add']),'edit':bool(r['can_edit']),'delete':bool(r['can_delete'])} for r in rows}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'hospitaladmin' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def perm_required(module, action='view'):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'hospitaladmin' not in session:
                return redirect(url_for('login'))
            user = get_user()
            if user.get('roles') == 'Super Admin':
                return f(*args, **kwargs)
            perms = get_user_permissions()
            if not perms.get(module, {}).get(action):
                flash(f'Access denied: {action} permission required for {module}.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def audit(action, module, record_id=0, details=''):
    try:
        user = get_user()
        edb("INSERT INTO audit_log (user_id,user_name,action,module,record_id,details,ip_address) VALUES (?,?,?,?,?,?,?)",
            (user.get('id',0), user.get('username',''), action, module, record_id, details, request.remote_addr))
    except: pass

@app.context_processor
def inject_globals():
    user = get_user()
    perms = get_user_permissions() if user else {}
    settings = {}
    if user:
        try:
            rows = qdb("SELECT name,value FROM sch_settings")
            settings = {r['name']: r['value'] for r in rows}
        except: pass
    return dict(current_user=type('U', (), user)() if user else None,
                user_perms=perms, settings=settings,
                ALL_MODULES=ALL_MODULES)

# ─────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS sch_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, role_id INTEGER NOT NULL,
    module TEXT NOT NULL, can_view INTEGER DEFAULT 0, can_add INTEGER DEFAULT 0,
    can_edit INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
    UNIQUE(role_id, module), FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS department (
    id INTEGER PRIMARY KEY AUTOINCREMENT, department_name TEXT NOT NULL,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS staff_designation (
    id INTEGER PRIMARY KEY AUTOINCREMENT, designation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT UNIQUE,
    name TEXT NOT NULL, surname TEXT DEFAULT '', email TEXT UNIQUE,
    password TEXT DEFAULT '', phone TEXT DEFAULT '', mobileno TEXT DEFAULT '',
    gender TEXT DEFAULT '', dob TEXT DEFAULT '', blood_group TEXT DEFAULT '',
    date_of_joining TEXT DEFAULT '', address TEXT DEFAULT '',
    department INTEGER DEFAULT 0, designation INTEGER DEFAULT 0,
    qualification TEXT DEFAULT '', experience TEXT DEFAULT '',
    basic_salary REAL DEFAULT 0, bank_name TEXT DEFAULT '',
    bank_account TEXT DEFAULT '', emergency_contact TEXT DEFAULT '',
    note TEXT DEFAULT '', is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (department) REFERENCES department(id)
);
CREATE TABLE IF NOT EXISTS staff_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER UNIQUE,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (staff_id) REFERENCES staff(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_unique_id TEXT UNIQUE,
    patient_name TEXT NOT NULL, guardian_name TEXT DEFAULT '',
    gender TEXT DEFAULT '', dob TEXT DEFAULT '', age INTEGER DEFAULT 0,
    blood_group TEXT DEFAULT '', mobile TEXT DEFAULT '',
    email TEXT DEFAULT '', address TEXT DEFAULT '',
    patient_type TEXT DEFAULT 'OPD', notes TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER DEFAULT 0, doctor_id INTEGER DEFAULT 0,
    appointment_date TEXT DEFAULT '', appointment_time TEXT DEFAULT '',
    department_id INTEGER DEFAULT 0, type TEXT DEFAULT 'OPD',
    status TEXT DEFAULT 'scheduled', priority TEXT DEFAULT 'normal',
    symptoms TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS opd_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, doctor_id INTEGER DEFAULT 0,
    date TEXT DEFAULT CURRENT_DATE, symptoms TEXT DEFAULT '',
    diagnosis TEXT DEFAULT '', charge REAL DEFAULT 0,
    payment_status TEXT DEFAULT 'unpaid', tpa_id INTEGER DEFAULT 0,
    follow_up_date TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS ipd_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, doctor_id INTEGER DEFAULT 0,
    bed INTEGER DEFAULT 0, date TEXT DEFAULT CURRENT_DATE,
    discharge_date TEXT DEFAULT '', discharged TEXT DEFAULT 'no',
    charge REAL DEFAULT 0, payment_status TEXT DEFAULT 'unpaid',
    tpa_id INTEGER DEFAULT 0, note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS bed_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_type TEXT NOT NULL, charge_per_day REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS floor (
    id INTEGER PRIMARY KEY AUTOINCREMENT, floor_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bed_group (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_group TEXT NOT NULL,
    floor_id INTEGER DEFAULT 0, description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS bed (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bed_name TEXT NOT NULL,
    bed_type_id INTEGER DEFAULT 0, bed_group_id INTEGER DEFAULT 0,
    is_active TEXT DEFAULT 'yes'
);
CREATE TABLE IF NOT EXISTS medicine_category (
    id INTEGER PRIMARY KEY AUTOINCREMENT, medicine_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pharmacy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_name TEXT NOT NULL, medicine_company TEXT DEFAULT '',
    medicine_composition TEXT DEFAULT '', medicine_category_id INTEGER DEFAULT 0,
    medicine_group TEXT DEFAULT '', unit TEXT DEFAULT 'Tablet',
    reorder_level INTEGER DEFAULT 10
);
CREATE TABLE IF NOT EXISTS medicine_batch_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT, pharmacy_id INTEGER NOT NULL,
    batch_no TEXT DEFAULT '', manufacture_date TEXT DEFAULT '',
    expiry_date TEXT DEFAULT '', purchase_price REAL DEFAULT 0,
    sale_price REAL DEFAULT 0, available_quantity INTEGER DEFAULT 0,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
-- NEW: Medicine dispensing to patients
CREATE TABLE IF NOT EXISTS medicine_dispense (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL, pharmacy_id INTEGER NOT NULL,
    batch_id INTEGER DEFAULT 0, quantity INTEGER DEFAULT 1,
    sale_price REAL DEFAULT 0, total_amount REAL DEFAULT 0,
    dispense_date TEXT DEFAULT CURRENT_DATE,
    dispensed_by INTEGER DEFAULT 0, opd_id INTEGER DEFAULT 0,
    ipd_id INTEGER DEFAULT 0, note TEXT DEFAULT '',
    payment_status TEXT DEFAULT 'paid',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
-- NEW: Stock purchase / stock-in
CREATE TABLE IF NOT EXISTS medicine_purchase (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pharmacy_id INTEGER NOT NULL, supplier_name TEXT DEFAULT '',
    invoice_no TEXT DEFAULT '', purchase_date TEXT DEFAULT CURRENT_DATE,
    batch_no TEXT DEFAULT '', manufacture_date TEXT DEFAULT '',
    expiry_date TEXT DEFAULT '', purchase_price REAL DEFAULT 0,
    sale_price REAL DEFAULT 0, quantity INTEGER DEFAULT 0,
    total_cost REAL DEFAULT 0, note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pharmacy_id) REFERENCES pharmacy(id)
);
CREATE TABLE IF NOT EXISTS expense_head (
    id INTEGER PRIMARY KEY AUTOINCREMENT, exp_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    exp_head_id INTEGER DEFAULT 0, invoice_no TEXT DEFAULT '',
    amount REAL DEFAULT 0, date TEXT DEFAULT CURRENT_DATE, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS income_head (
    id INTEGER PRIMARY KEY AUTOINCREMENT, income_category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS income (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    income_head_id INTEGER DEFAULT 0, invoice_no TEXT DEFAULT '',
    amount REAL DEFAULT 0, date TEXT DEFAULT CURRENT_DATE, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS payroll (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    month TEXT DEFAULT '', year INTEGER DEFAULT 0,
    basic_salary REAL DEFAULT 0, allowances REAL DEFAULT 0,
    deductions REAL DEFAULT 0, net_salary REAL DEFAULT 0,
    payment_status TEXT DEFAULT 'unpaid', payment_date TEXT DEFAULT '',
    note TEXT DEFAULT '',
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS lab_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
    test_name TEXT NOT NULL, doctor_id INTEGER DEFAULT 0,
    test_date TEXT DEFAULT CURRENT_DATE, result TEXT DEFAULT '',
    normal_range TEXT DEFAULT '', unit TEXT DEFAULT '',
    status TEXT DEFAULT 'pending', note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS userlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER DEFAULT 0,
    action TEXT DEFAULT 'login', ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_name TEXT NOT NULL,
    patient_id INTEGER DEFAULT 0, purpose TEXT DEFAULT '',
    visit_date TEXT DEFAULT CURRENT_DATE, visit_time TEXT DEFAULT '',
    note TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tpa (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_name TEXT NOT NULL, contact_person TEXT DEFAULT '',
    email TEXT DEFAULT '', phone TEXT DEFAULT '', address TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1, coverage_limit REAL DEFAULT 0,
    policy_details TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS vehicle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_name TEXT NOT NULL, vehicle_number TEXT DEFAULT '',
    vehicle_type TEXT DEFAULT 'ambulance', driver_name TEXT DEFAULT '',
    driver_phone TEXT DEFAULT '', status TEXT DEFAULT 'available',
    last_maintenance TEXT DEFAULT '', fuel_type TEXT DEFAULT 'Diesel'
);
CREATE TABLE IF NOT EXISTS vehicle_trips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id INTEGER NOT NULL, patient_id INTEGER DEFAULT 0,
    trip_date TEXT DEFAULT CURRENT_DATE, pickup_location TEXT DEFAULT '',
    drop_location TEXT DEFAULT '', distance_km REAL DEFAULT 0,
    charge REAL DEFAULT 0, driver_id INTEGER DEFAULT 0,
    status TEXT DEFAULT 'completed', note TEXT DEFAULT '',
    FOREIGN KEY (vehicle_id) REFERENCES vehicle(id)
);
CREATE TABLE IF NOT EXISTS leave_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    days_allowed INTEGER DEFAULT 0, carry_forward INTEGER DEFAULT 0,
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS leave_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    leave_type_id INTEGER NOT NULL, from_date TEXT NOT NULL,
    to_date TEXT NOT NULL, total_days INTEGER DEFAULT 1,
    reason TEXT DEFAULT '', status TEXT DEFAULT 'pending',
    approved_by INTEGER DEFAULT 0, approved_date TEXT DEFAULT '',
    note TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    date TEXT NOT NULL, time_in TEXT DEFAULT '', time_out TEXT DEFAULT '',
    status TEXT DEFAULT 'present', note TEXT DEFAULT '',
    FOREIGN KEY (staff_id) REFERENCES staff(id), UNIQUE(staff_id, date)
);
CREATE TABLE IF NOT EXISTS performance_appraisal (
    id INTEGER PRIMARY KEY AUTOINCREMENT, staff_id INTEGER NOT NULL,
    period TEXT NOT NULL, reviewer_id INTEGER DEFAULT 0,
    punctuality INTEGER DEFAULT 0, teamwork INTEGER DEFAULT 0,
    technical_skills INTEGER DEFAULT 0, communication INTEGER DEFAULT 0,
    patient_care INTEGER DEFAULT 0, overall_score REAL DEFAULT 0,
    grade TEXT DEFAULT '', strengths TEXT DEFAULT '', improvements TEXT DEFAULT '',
    goals TEXT DEFAULT '', reviewer_comments TEXT DEFAULT '',
    status TEXT DEFAULT 'draft', review_date TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (staff_id) REFERENCES staff(id)
);
CREATE TABLE IF NOT EXISTS training (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
    category TEXT DEFAULT '', trainer TEXT DEFAULT '',
    start_date TEXT DEFAULT '', end_date TEXT DEFAULT '',
    duration_hours INTEGER DEFAULT 0, location TEXT DEFAULT '',
    description TEXT DEFAULT '', is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS training_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT, training_id INTEGER NOT NULL,
    staff_id INTEGER NOT NULL, status TEXT DEFAULT 'enrolled',
    score INTEGER DEFAULT 0, certificate_issued INTEGER DEFAULT 0,
    completion_date TEXT DEFAULT '',
    FOREIGN KEY (training_id) REFERENCES training(id),
    FOREIGN KEY (staff_id) REFERENCES staff(id),
    UNIQUE(training_id, staff_id)
);
CREATE TABLE IF NOT EXISTS blood_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT, blood_group TEXT NOT NULL UNIQUE,
    units_available INTEGER DEFAULT 0, last_updated TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blood_donations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, donor_name TEXT NOT NULL,
    blood_group TEXT NOT NULL, donor_contact TEXT DEFAULT '',
    donor_age INTEGER DEFAULT 0, donation_date TEXT DEFAULT CURRENT_DATE,
    units_donated INTEGER DEFAULT 1, status TEXT DEFAULT 'available',
    expiry_date TEXT DEFAULT '', note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blood_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER DEFAULT 0,
    blood_group TEXT NOT NULL, units_required INTEGER DEFAULT 1,
    request_date TEXT DEFAULT CURRENT_DATE, required_date TEXT DEFAULT '',
    doctor_id INTEGER DEFAULT 0, status TEXT DEFAULT 'pending',
    purpose TEXT DEFAULT '', note TEXT DEFAULT '',
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER DEFAULT 0,
    user_name TEXT DEFAULT '', action TEXT DEFAULT '',
    module TEXT DEFAULT '', record_id INTEGER DEFAULT 0,
    details TEXT DEFAULT '', ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


# ─────────────────────────────────────────────
# SEED DATA
# ─────────────────────────────────────────────
def seed_data(db):
    # Check if already seeded
    existing = db.execute("SELECT COUNT(*) as c FROM staff").fetchone()['c']
    if existing > 0:
        return

    today = date.today().isoformat()

    # Settings
    settings = [
        ('name','Trinetra Hospital'),('email','admin@hospital.com'),
        ('phone','+1-555-000-0000'),('address','123 Medical Drive, Healthcare City'),
        ('currency','USD'),('currency_symbol','$'),('timezone','UTC'),
        ('date_format','d-m-Y'),('time_format','12'),('theme','default')
    ]
    for k,v in settings:
        db.execute("INSERT OR IGNORE INTO sch_settings (name,value) VALUES (?,?)", (k,v))

    # Roles
    roles = [
        ('Super Admin','Full system access'),('Admin','System administration'),
        ('Doctor','Clinical access'),('Nurse','Ward and patient care'),
        ('Pharmacist','Pharmacy management'),('Receptionist','Front desk operations'),
        ('Accountant','Finance and billing'),('HR Manager','Human resources'),
        ('Lab Technician','Laboratory operations'),
    ]
    for name,desc in roles:
        db.execute("INSERT OR IGNORE INTO roles (name,description) VALUES (?,?)", (name,desc))
    db.commit()

    # Role permissions
    role_map = {r['name']:r['id'] for r in db.execute("SELECT id,name FROM roles").fetchall()}
    admin_skip = set()  # modules admin can't touch
    super_admin_id = role_map.get('Super Admin',1)

    module_perms = {
        'Admin':     {m:(1,1,1,1) for m in ALL_MODULES if m!='admin'},
        'Doctor':    {m:(1,0,0,0) for m in ['dashboard','patients','opd','ipd','beds','lab','appointments','bloodbank']},
        'Nurse':     {m:(1,0,0,0) for m in ['dashboard','patients','opd','ipd','beds','lab']},
        'Pharmacist':{m:(1,1,1,0) for m in ['dashboard','patients','pharmacy']},
        'Receptionist':{m:(1,1,0,0) for m in ['dashboard','patients','appointments','opd','visitors']},
        'Accountant':{m:(1,1,1,0) for m in ['dashboard','income','expenses','reports','payroll','insurance']},
        'HR Manager':{m:(1,1,1,0) for m in ['dashboard','staff','payroll','hr_leave','hr_attendance','hr_appraisal','hr_training']},
        'Lab Technician':{m:(1,1,1,0) for m in ['dashboard','patients','lab']},
    }
    for role_name, mods in module_perms.items():
        rid = role_map.get(role_name)
        if not rid: continue
        for mod,(v,a,e,d) in mods.items():
            db.execute("INSERT OR IGNORE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",
                       (rid,mod,v,a,e,d))
    db.commit()

    # Departments
    depts = ['Cardiology','Orthopedics','Neurology','Pediatrics','General Medicine',
             'Emergency','Gynecology','Oncology','Radiology','Psychiatry','Dermatology','ENT','Pharmacy','Administration']
    for d in depts:
        db.execute("INSERT OR IGNORE INTO department (department_name) VALUES (?)", (d,))
    db.commit()
    dept_map = {r['department_name']:r['id'] for r in db.execute("SELECT id,department_name FROM department").fetchall()}

    # Designations
    desigs = ['Senior Consultant','Junior Doctor','Resident Doctor','Head Nurse','Staff Nurse',
              'Chief Pharmacist','Pharmacist','Lab Head','Lab Technician','Admin Officer','HR Manager','Accountant']
    for d in desigs:
        db.execute("INSERT OR IGNORE INTO staff_designation (designation) VALUES (?)", (d,))
    db.commit()
    desig_map = {r['designation']:r['id'] for r in db.execute("SELECT id,designation FROM staff_designation").fetchall()}

    # Staff users
    staff_list = [
        ('EMP001','Admin','User','admin@hospital.com','admin123','+1-555-0001','Super Admin','Administration','Admin Officer',50000),
        ('EMP002','Dr. John','Smith','doctor@hospital.com','admin123','+1-555-0002','Doctor','General Medicine','Senior Consultant',80000),
        ('EMP003','Mary','Johnson','nurse@hospital.com','admin123','+1-555-0003','Nurse','General Medicine','Head Nurse',40000),
        ('EMP004','David','Lee','pharmacist@hospital.com','admin123','+1-555-0004','Pharmacist','Pharmacy','Chief Pharmacist',45000),
        ('EMP005','Sara','Wilson','reception@hospital.com','admin123','+1-555-0005','Receptionist','Administration','Admin Officer',35000),
        ('EMP006','Tom','Davis','accounts@hospital.com','admin123','+1-555-0006','Accountant','Administration','Accountant',42000),
        ('EMP007','Linda','Brown','hr@hospital.com','admin123','+1-555-0007','HR Manager','Administration','HR Manager',43000),
        ('EMP008','Dr. Emily','Chen','doctor2@hospital.com','admin123','+1-555-0008','Doctor','Cardiology','Senior Consultant',85000),
    ]
    for emp_id,name,surname,email,pw,phone,role_name,dept_name,desig_name,salary in staff_list:
        dept_id = dept_map.get(dept_name,1)
        desig_id = desig_map.get(desig_name,1)
        sid = db.execute("INSERT OR IGNORE INTO staff (employee_id,name,surname,email,password,phone,mobileno,gender,date_of_joining,department,designation,basic_salary,blood_group) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (emp_id,name,surname,email,hash_pw(pw),phone,phone,'Male' if name.startswith('Dr. J') or name in ['David','Tom'] else 'Female',
             today,dept_id,desig_id,salary,'O+')).lastrowid
        role_id = role_map.get(role_name,1)
        db.execute("INSERT OR IGNORE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
    db.commit()

    # Medicine categories
    cats = ['Tablet','Capsule','Syrup','Injection','Cream/Ointment','Eye Drops','Ear Drops','Inhaler','Powder','Suspension']
    for c in cats:
        db.execute("INSERT OR IGNORE INTO medicine_category (medicine_category) VALUES (?)", (c,))
    db.commit()
    cat_map = {r['medicine_category']:r['id'] for r in db.execute("SELECT id,medicine_category FROM medicine_category").fetchall()}

    # Medicines with stock
    medicines = [
        ('Paracetamol 500mg','PharmaCo','Paracetamol','Tablet','Analgesic',5.00,10.00,500),
        ('Amoxicillin 250mg','MediLab','Amoxicillin','Capsule','Antibiotic',15.00,30.00,200),
        ('Omeprazole 20mg','HealthPharma','Omeprazole','Tablet','Antacid',8.00,18.00,300),
        ('Metformin 500mg','DiabCare','Metformin','Tablet','Antidiabetic',6.00,12.00,400),
        ('Cetirizine 10mg','AllerCure','Cetirizine','Tablet','Antihistamine',4.00,9.00,350),
        ('Azithromycin 500mg','MediLab','Azithromycin','Tablet','Antibiotic',25.00,50.00,150),
        ('Ibuprofen 400mg','PharmaCo','Ibuprofen','Tablet','Anti-inflammatory',7.00,14.00,300),
        ('Atorvastatin 10mg','CardioMed','Atorvastatin','Tablet','Lipid-lowering',12.00,24.00,200),
        ('Cough Syrup 100ml','SyrupLab','Dextromethorphan','Syrup','Antitussive',18.00,35.00,100),
        ('Insulin Regular','DiabCare','Human Insulin','Injection','Antidiabetic',45.00,90.00,80),
    ]
    for name,company,comp,cat_name,grp,pp,sp,qty in medicines:
        cat_id = cat_map.get(cat_name,1)
        mid = db.execute("INSERT OR IGNORE INTO pharmacy (medicine_name,medicine_company,medicine_composition,medicine_category_id,medicine_group,unit,reorder_level) VALUES (?,?,?,?,?,?,?)",
            (name,company,comp,cat_id,grp,cat_name,20)).lastrowid
        if mid:
            expiry = (date.today() + timedelta(days=365)).isoformat()
            db.execute("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
                (mid,f'B{mid:04d}',today,expiry,pp,sp,qty))
    db.commit()

    # Bed types, floors, groups, beds
    bed_types = [('General Ward',200),('Semi-Private',400),('Private',800),('ICU',2000),('NICU',2500),('Emergency',500)]
    for bt,charge in bed_types:
        db.execute("INSERT OR IGNORE INTO bed_type (bed_type,charge_per_day) VALUES (?,?)", (bt,charge))
    floors = ['Ground Floor','First Floor','Second Floor','Third Floor']
    for f_ in floors:
        db.execute("INSERT OR IGNORE INTO floor (floor_name) VALUES (?)", (f_,))
    db.commit()
    fl_id = db.execute("SELECT id FROM floor LIMIT 1").fetchone()['id']
    db.execute("INSERT OR IGNORE INTO bed_group (bed_group,floor_id) VALUES ('Ward A',?)", (fl_id,))
    db.execute("INSERT OR IGNORE INTO bed_group (bed_group,floor_id) VALUES ('Ward B',?)", (fl_id,))
    db.commit()
    grp_id = db.execute("SELECT id FROM bed_group LIMIT 1").fetchone()['id']
    bt_id  = db.execute("SELECT id FROM bed_type LIMIT 1").fetchone()['id']
    for i in range(1,21):
        db.execute("INSERT OR IGNORE INTO bed (bed_name,bed_type_id,bed_group_id) VALUES (?,?,?)", (f'B{i:03d}',bt_id,grp_id))
    db.commit()

    # Sample patients
    import random
    names = [('Ravi','Kumar'),('Priya','Sharma'),('Ahmed','Khan'),('Susan','Miller'),
             ('Carlos','Lopez'),('Fatima','Ali'),('James','Wilson'),('Meera','Patel'),
             ('Robert','Brown'),('Aisha','Noor')]
    for i,(fn,ln) in enumerate(names,1):
        pid = f'PID{i:04d}'
        age = random.randint(18,75)
        db.execute("INSERT OR IGNORE INTO patients (patient_unique_id,patient_name,guardian_name,gender,age,blood_group,mobile,email,address,patient_type) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (pid,f'{fn} {ln}',f'Guardian of {fn}','Male' if i%2==0 else 'Female',age,
             random.choice(['A+','B+','O+','AB+','A-','O-']),
             f'+1-555-{i:04d}',f'{fn.lower()}.{ln.lower()}@email.com',
             f'{i} Main Street, City','OPD'))
    db.commit()

    # Leave types
    leave_types = [('Annual Leave',15,1,'Yearly annual leave'),('Sick Leave',12,0,'Medical sick leave'),
                   ('Casual Leave',7,0,'Casual/personal leave'),('Maternity Leave',90,0,'Maternity leave'),
                   ('Emergency Leave',3,0,'Emergency leave')]
    for name,days,cf,desc in leave_types:
        db.execute("INSERT OR IGNORE INTO leave_types (name,days_allowed,carry_forward,description) VALUES (?,?,?,?)", (name,days,cf,desc))

    # Income/expense heads
    for cat in ['OPD Charges','IPD Charges','Lab Charges','Pharmacy Sales','Ambulance','Consultation','Other Income']:
        db.execute("INSERT OR IGNORE INTO income_head (income_category) VALUES (?)", (cat,))
    for cat in ['Medicines Purchase','Salaries','Maintenance','Utilities','Equipment','Consumables','Other Expense']:
        db.execute("INSERT OR IGNORE INTO expense_head (exp_category) VALUES (?)", (cat,))

    # TPA
    db.execute("INSERT OR IGNORE INTO tpa (organisation_name,contact_person,email,phone,coverage_limit,is_active) VALUES ('Star Health Insurance','Mr. Rajan','rajan@starhealth.com','+91-9000000001',100000,1)")
    db.execute("INSERT OR IGNORE INTO tpa (organisation_name,contact_person,email,phone,coverage_limit,is_active) VALUES ('United Health Care','Ms. Priya','priya@uhc.com','+91-9000000002',200000,1)")

    # Vehicles
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Ambulance 1','AMB-001','ambulance','Raju Kumar','+1-555-9001','available')")
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Ambulance 2','AMB-002','ambulance','Sita Ram','+1-555-9002','available')")
    db.execute("INSERT OR IGNORE INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,status) VALUES ('Staff Van','VAN-001','van','Mohan Das','+1-555-9003','available')")

    # Blood inventory
    for bg in ['A+','A-','B+','B-','AB+','AB-','O+','O-']:
        import random as rnd
        db.execute("INSERT OR IGNORE INTO blood_inventory (blood_group,units_available) VALUES (?,?)", (bg,rnd.randint(5,30)))

    # Training programs
    db.execute("INSERT OR IGNORE INTO training (title,category,trainer,start_date,end_date,duration_hours,location) VALUES ('Basic Life Support & CPR','Clinical','Dr. John Smith',?,?,8,'Seminar Hall')", (today,today))
    db.execute("INSERT OR IGNORE INTO training (title,category,trainer,start_date,end_date,duration_hours,location) VALUES ('Infection Control Protocol','Safety','Linda Brown',?,?,4,'Training Room')", (today,today))

    # Sample income/expenses for last 7 days
    ihead_id = db.execute("SELECT id FROM income_head LIMIT 1").fetchone()['id']
    ehead_id = db.execute("SELECT id FROM expense_head LIMIT 1").fetchone()['id']
    for i in range(7):
        d = (date.today() - timedelta(days=i)).isoformat()
        import random as rnd
        db.execute("INSERT INTO income (name,income_head_id,amount,date,invoice_no) VALUES (?,?,?,?,?)",
            ('OPD Collection',ihead_id,rnd.randint(2000,8000),d,f'INV-{i:04d}'))
        db.execute("INSERT INTO expenses (name,exp_head_id,amount,date,invoice_no) VALUES (?,?,?,?,?)",
            ('Daily Supplies',ehead_id,rnd.randint(500,2000),d,f'EXP-{i:04d}'))

    db.commit()
    print("[HMS v3] Seed data inserted.")

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(SCHEMA)
    db.commit()
    seed_data(db)
    db.close()
    print("[HMS v3] Database initialized.")


# ─────────────────────────────────────────────
# LOGIN / LOGOUT
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'hospitaladmin' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username','').strip()
        pw    = hash_pw(request.form.get('password',''))
        user  = qdb("SELECT staff.*,roles.name as role_name,roles.id as role_id FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id LEFT JOIN roles ON roles.id=staff_roles.role_id WHERE (staff.email=? OR staff.employee_id=?) AND staff.password=? AND staff.is_active=1",
                    (email,email,pw), one=True)
        if user:
            settings = {r['name']:r['value'] for r in qdb("SELECT name,value FROM sch_settings")}
            session['hospitaladmin'] = {
                'id': user['id'], 'username': user['name']+' '+user['surname'],
                'email': user['email'], 'roles': user['role_name'],
                'role_id': user['role_id'], 'employee_id': user['employee_id'],
                'currency_symbol': settings.get('currency_symbol','$'),
                'school_name': settings.get('name','Hospital')
            }
            edb("INSERT INTO userlog (staff_id,action,ip_address) VALUES (?,?,?)", (user['id'],'login',request.remote_addr))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_user()
    if user:
        edb("INSERT INTO userlog (staff_id,action,ip_address) VALUES (?,?,?)", (user.get('id',0),'logout',request.remote_addr))
    session.pop('hospitaladmin', None)
    return redirect(url_for('login'))

# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    today = date.today().isoformat()
    stats = {
        'total_patients': qdb("SELECT COUNT(*) as c FROM patients WHERE is_active=1", one=True)['c'],
        'opd_today': qdb("SELECT COUNT(*) as c FROM opd_details WHERE date=?", (today,), one=True)['c'],
        'ipd_current': qdb("SELECT COUNT(*) as c FROM ipd_details WHERE discharged='no'", one=True)['c'],
        'beds_available': qdb("SELECT COUNT(*) as c FROM bed WHERE is_active='yes' AND id NOT IN (SELECT bed FROM ipd_details WHERE discharged='no' AND bed>0)", one=True)['c'],
        'staff_active': qdb("SELECT COUNT(*) as c FROM staff WHERE is_active=1", one=True)['c'],
        'medicines': qdb("SELECT COUNT(*) as c FROM pharmacy", one=True)['c'],
        'appointments_today': qdb("SELECT COUNT(*) as c FROM appointments WHERE appointment_date=?", (today,), one=True)['c'],
        'pending_leaves': qdb("SELECT COUNT(*) as c FROM leave_applications WHERE status='pending'", one=True)['c'],
        'total_income': qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date=?", (today,), one=True)['s'],
        'total_expense': qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date=?", (today,), one=True)['s'],
        'blood_units': qdb("SELECT COALESCE(SUM(units_available),0) as s FROM blood_inventory", one=True)['s'],
        'pending_lab': qdb("SELECT COUNT(*) as c FROM lab_reports WHERE status='pending'", one=True)['c'],
        'dispense_today': qdb("SELECT COUNT(*) as c FROM medicine_dispense WHERE dispense_date=?", (today,), one=True)['c'],
    }
    appointments_today = qdb("""SELECT appointments.*,patients.patient_name,
        staff.name||' '||staff.surname as doctor_name
        FROM appointments LEFT JOIN patients ON patients.id=appointments.patient_id
        LEFT JOIN staff ON staff.id=appointments.doctor_id
        WHERE appointment_date=? ORDER BY appointment_time""", (today,))
    pending_leaves = qdb("""SELECT leave_applications.*,staff.name,staff.surname,staff.employee_id,leave_types.name as leave_name
        FROM leave_applications JOIN staff ON staff.id=leave_applications.staff_id
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        WHERE leave_applications.status='pending' ORDER BY leave_applications.id DESC LIMIT 5""")
    expiry_alerts = qdb("""SELECT pharmacy.medicine_name,medicine_batch_details.expiry_date,medicine_batch_details.available_quantity
        FROM medicine_batch_details JOIN pharmacy ON pharmacy.id=medicine_batch_details.pharmacy_id
        WHERE medicine_batch_details.expiry_date<=? AND medicine_batch_details.available_quantity>0
        ORDER BY medicine_batch_details.expiry_date""", ((date.today()+timedelta(days=30)).isoformat(),))
    recent_patients = qdb("SELECT * FROM patients ORDER BY id DESC LIMIT 5")
    return render_template('dashboard.html', stats=stats, appointments_today=appointments_today,
                           pending_leaves=pending_leaves, expiry_alerts=expiry_alerts, recent_patients=recent_patients)

@app.route('/api/chart')
@login_required
def api_chart():
    labels, income_data, expense_data, opd_data = [], [], [], []
    for i in range(6,-1,-1):
        d = (date.today()-timedelta(days=i)).isoformat()
        labels.append(d[5:])
        income_data.append(qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date=?", (d,), one=True)['s'])
        expense_data.append(qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date=?", (d,), one=True)['s'])
        opd_data.append(qdb("SELECT COUNT(*) as c FROM opd_details WHERE date=?", (d,), one=True)['c'])
    return jsonify({'labels':labels,'income':income_data,'expense':expense_data,'opd':opd_data})

# ─────────────────────────────────────────────
# APPOINTMENTS
# ─────────────────────────────────────────────
@app.route('/appointments')
@perm_required('appointments','view')
def appointments():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("""SELECT appointments.*,patients.patient_name,
        staff.name||' '||staff.surname as doctor_name,department.department_name
        FROM appointments LEFT JOIN patients ON patients.id=appointments.patient_id
        LEFT JOIN staff ON staff.id=appointments.doctor_id
        LEFT JOIN department ON department.id=appointments.department_id
        WHERE appointment_date=? ORDER BY appointment_time""", (date_filter,))
    return render_template('appointments/list.html', records=rows, date_filter=date_filter)

@app.route('/appointments/add', methods=['GET','POST'])
@perm_required('appointments','add')
def appointment_add():
    if request.method == 'POST':
        f = request.form
        aid = edb("INSERT INTO appointments (patient_id,doctor_id,appointment_date,appointment_time,department_id,type,priority,symptoms,note) VALUES (?,?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('appointment_date',date.today().isoformat()),
             f.get('appointment_time',''),f.get('department_id',0),f.get('type','OPD'),
             f.get('priority','normal'),f.get('symptoms',''),f.get('note','')))
        audit('create','appointments',aid,'New appointment added')
        flash('Appointment booked.','success')
        return redirect(url_for('appointments'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT staff.*,department.department_name FROM staff LEFT JOIN department ON department.id=staff.department WHERE staff.is_active=1 ORDER BY staff.name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    return render_template('appointments/add.html', patients=patients, doctors=doctors, departments=departments, today=date.today().isoformat())

@app.route('/appointments/<int:aid>/status', methods=['POST'])
@perm_required('appointments','edit')
def appointment_status(aid):
    edb("UPDATE appointments SET status=? WHERE id=?", (request.form.get('status','completed'),aid))
    flash('Status updated.','success')
    return redirect(url_for('appointments'))

# ─────────────────────────────────────────────
# PATIENTS
# ─────────────────────────────────────────────
@app.route('/patients')
@perm_required('patients','view')
def patients():
    search = request.args.get('q','')
    if search:
        rows = qdb("SELECT * FROM patients WHERE is_active=1 AND (patient_name LIKE ? OR patient_unique_id LIKE ? OR mobile LIKE ?) ORDER BY id DESC",
                   (f'%{search}%',f'%{search}%',f'%{search}%'))
    else:
        rows = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY id DESC")
    return render_template('patients/list.html', patients=rows, search=search)

@app.route('/patients/add', methods=['GET','POST'])
@perm_required('patients','add')
def patient_add():
    if request.method == 'POST':
        f = request.form
        # Auto-generate patient ID
        count = qdb("SELECT COUNT(*) as c FROM patients", one=True)['c']
        pid_str = f'PID{count+1:04d}'
        new_id = edb("INSERT INTO patients (patient_unique_id,patient_name,guardian_name,gender,dob,age,blood_group,mobile,email,address,patient_type,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid_str,f.get('patient_name'),f.get('guardian_name'),f.get('gender'),f.get('dob',''),
             f.get('age',0),f.get('blood_group'),f.get('mobile'),f.get('email'),f.get('address'),f.get('patient_type','OPD'),f.get('notes','')))
        audit('create','patients',new_id,f'Patient {f.get("patient_name")} added')
        flash(f'Patient added with ID: {pid_str}','success')
        return redirect(url_for('patient_view',pid=new_id))
    return render_template('patients/add.html')

@app.route('/patients/<int:pid>')
@perm_required('patients','view')
def patient_view(pid):
    p = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    if not p: abort(404)
    opd_records = qdb("""SELECT opd_details.*,staff.name||' '||staff.surname as doctor_name,tpa.organisation_name as tpa_name
        FROM opd_details LEFT JOIN staff ON staff.id=opd_details.doctor_id
        LEFT JOIN tpa ON tpa.id=opd_details.tpa_id
        WHERE opd_details.patient_id=? ORDER BY opd_details.id DESC""", (pid,))
    ipd_records = qdb("""SELECT ipd_details.*,staff.name||' '||staff.surname as doctor_name,
        bed.bed_name FROM ipd_details LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        LEFT JOIN bed ON bed.id=ipd_details.bed
        WHERE ipd_details.patient_id=? ORDER BY ipd_details.id DESC""", (pid,))
    lab_records = qdb("SELECT * FROM lab_reports WHERE patient_id=? ORDER BY id DESC", (pid,))
    appointments = qdb("""SELECT appointments.*,staff.name||' '||staff.surname as doctor_name
        FROM appointments LEFT JOIN staff ON staff.id=appointments.doctor_id
        WHERE appointments.patient_id=? ORDER BY appointments.id DESC""", (pid,))
    dispenses = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.patient_id=? ORDER BY medicine_dispense.id DESC""", (pid,))
    blood_requests = qdb("SELECT * FROM blood_requests WHERE patient_id=? ORDER BY id DESC", (pid,))
    return render_template('patients/view.html', patient=dict(p), opd_records=opd_records,
                           ipd_records=ipd_records, lab_records=lab_records, appointments=appointments,
                           dispenses=dispenses, blood_requests=blood_requests)

@app.route('/patients/<int:pid>/edit', methods=['GET','POST'])
@perm_required('patients','edit')
def patient_edit(pid):
    p = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    if not p: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("UPDATE patients SET patient_name=?,guardian_name=?,gender=?,dob=?,age=?,blood_group=?,mobile=?,email=?,address=?,patient_type=?,notes=? WHERE id=?",
            (f.get('patient_name'),f.get('guardian_name'),f.get('gender'),f.get('dob'),f.get('age',0),
             f.get('blood_group'),f.get('mobile'),f.get('email'),f.get('address'),f.get('patient_type','OPD'),f.get('notes',''),pid))
        flash('Patient updated.','success')
        return redirect(url_for('patient_view',pid=pid))
    return render_template('patients/edit.html', patient=dict(p))

@app.route('/patients/<int:pid>/delete', methods=['POST'])
@perm_required('patients','delete')
def patient_delete(pid):
    edb("UPDATE patients SET is_active=0 WHERE id=?", (pid,))
    flash('Patient removed.','success')
    return redirect(url_for('patients'))

# ─────────────────────────────────────────────
# OPD
# ─────────────────────────────────────────────
@app.route('/opd')
@perm_required('opd','view')
def opd():
    rows = qdb("""SELECT opd_details.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name,tpa.organisation_name as tpa_name
        FROM opd_details LEFT JOIN patients ON patients.id=opd_details.patient_id
        LEFT JOIN staff ON staff.id=opd_details.doctor_id
        LEFT JOIN tpa ON tpa.id=opd_details.tpa_id
        ORDER BY opd_details.id DESC LIMIT 200""")
    return render_template('opd/list.html', records=rows)

@app.route('/opd/add', methods=['GET','POST'])
@perm_required('opd','add')
def opd_add():
    if request.method == 'POST':
        f = request.form
        oid = edb("INSERT INTO opd_details (patient_id,doctor_id,date,symptoms,diagnosis,charge,payment_status,tpa_id,follow_up_date,note) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('date',date.today().isoformat()),
             f.get('symptoms',''),f.get('diagnosis',''),f.get('charge',0),
             f.get('payment_status','unpaid'),f.get('tpa_id',0),f.get('follow_up_date',''),f.get('note','')))
        audit('create','opd',oid,'OPD visit added')
        flash('OPD record added.','success')
        return redirect(url_for('opd'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    tpa_list = qdb("SELECT * FROM tpa WHERE is_active=1 ORDER BY organisation_name")
    return render_template('opd/add.html', patients=patients, doctors=doctors, tpa_list=tpa_list, today=date.today().isoformat())

# ─────────────────────────────────────────────
# IPD
# ─────────────────────────────────────────────
@app.route('/ipd')
@perm_required('ipd','view')
def ipd():
    rows = qdb("""SELECT ipd_details.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name, bed.bed_name
        FROM ipd_details LEFT JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        LEFT JOIN bed ON bed.id=ipd_details.bed
        ORDER BY ipd_details.id DESC""")
    return render_template('ipd/list.html', records=rows)

@app.route('/ipd/add', methods=['GET','POST'])
@perm_required('ipd','add')
def ipd_add():
    if request.method == 'POST':
        f = request.form
        iid = edb("INSERT INTO ipd_details (patient_id,doctor_id,bed,date,charge,payment_status,tpa_id,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('doctor_id',0),f.get('bed_id',0),
             f.get('date',date.today().isoformat()),f.get('charge',0),
             f.get('payment_status','unpaid'),f.get('tpa_id',0),f.get('note','')))
        audit('create','ipd',iid,'IPD admission added')
        flash('Patient admitted.','success')
        return redirect(url_for('ipd'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    beds     = qdb("""SELECT bed.*,bed_type.bed_type,bed_type.charge_per_day FROM bed
        LEFT JOIN bed_type ON bed_type.id=bed.bed_type_id
        WHERE bed.is_active='yes' AND bed.id NOT IN (SELECT bed FROM ipd_details WHERE discharged='no' AND bed>0)
        ORDER BY bed.bed_name""")
    tpa_list = qdb("SELECT * FROM tpa WHERE is_active=1")
    return render_template('ipd/add.html', patients=patients, doctors=doctors, beds=beds, tpa_list=tpa_list, today=date.today().isoformat())

@app.route('/ipd/<int:iid>/discharge', methods=['POST'])
@perm_required('ipd','edit')
def ipd_discharge(iid):
    edb("UPDATE ipd_details SET discharged='yes',discharge_date=? WHERE id=?", (date.today().isoformat(),iid))
    flash('Patient discharged.','success')
    return redirect(url_for('ipd'))

# ─────────────────────────────────────────────
# BEDS
# ─────────────────────────────────────────────
@app.route('/beds')
@perm_required('beds','view')
def beds():
    rows = qdb("""SELECT bed.*,bed_type.bed_type,bed_type.charge_per_day,bed_group.bed_group,
        ipd_details.id as ipd_id, patients.patient_name, staff.name||' '||staff.surname as doctor_name,
        ipd_details.date as admission_date
        FROM bed LEFT JOIN bed_type ON bed_type.id=bed.bed_type_id
        LEFT JOIN bed_group ON bed_group.id=bed.bed_group_id
        LEFT JOIN ipd_details ON ipd_details.bed=bed.id AND ipd_details.discharged='no'
        LEFT JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id
        WHERE bed.is_active='yes' ORDER BY bed.bed_name""")
    total = len(rows)
    occupied = sum(1 for r in rows if r['ipd_id'])
    return render_template('beds/list.html', beds=rows, total=total, occupied=occupied, available=total-occupied)

@app.route('/beds/add', methods=['GET','POST'])
@perm_required('beds','add')
def beds_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO bed (bed_name,bed_type_id,bed_group_id) VALUES (?,?,?)",
            (f.get('bed_name'),f.get('bed_type_id',0),f.get('bed_group_id',0)))
        flash('Bed added.','success')
        return redirect(url_for('beds'))
    bed_types  = qdb("SELECT * FROM bed_type ORDER BY bed_type")
    bed_groups = qdb("SELECT bed_group.*,floor.floor_name FROM bed_group LEFT JOIN floor ON floor.id=bed_group.floor_id")
    return render_template('beds/add.html', bed_types=bed_types, bed_groups=bed_groups)

# ─────────────────────────────────────────────
# LABORATORY
# ─────────────────────────────────────────────
@app.route('/lab')
@perm_required('lab','view')
def lab():
    rows = qdb("""SELECT lab_reports.*,patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as doctor_name
        FROM lab_reports LEFT JOIN patients ON patients.id=lab_reports.patient_id
        LEFT JOIN staff ON staff.id=lab_reports.doctor_id
        ORDER BY lab_reports.id DESC""")
    return render_template('lab/list.html', records=rows)

@app.route('/lab/add', methods=['GET','POST'])
@perm_required('lab','add')
def lab_add():
    if request.method == 'POST':
        f = request.form
        lid = edb("INSERT INTO lab_reports (patient_id,test_name,doctor_id,test_date,normal_range,unit,note) VALUES (?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('test_name'),f.get('doctor_id',0),
             f.get('test_date',date.today().isoformat()),f.get('normal_range',''),f.get('unit',''),f.get('note','')))
        audit('create','lab',lid,'Lab test ordered')
        flash('Lab test ordered.','success')
        return redirect(url_for('lab'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    return render_template('lab/add.html', patients=patients, doctors=doctors, today=date.today().isoformat())

@app.route('/lab/<int:lid>/result', methods=['POST'])
@perm_required('lab','edit')
def lab_result(lid):
    edb("UPDATE lab_reports SET result=?,status='completed',note=? WHERE id=?",
        (request.form.get('result',''),request.form.get('note',''),lid))
    flash('Result updated.','success')
    return redirect(url_for('lab'))


# ─────────────────────────────────────────────
# PHARMACY — Full end-to-end
# ─────────────────────────────────────────────
@app.route('/pharmacy')
@perm_required('pharmacy','view')
def pharmacy_list():
    rows = qdb("""SELECT pharmacy.*,medicine_category.medicine_category,
        COALESCE((SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id),0) as total_qty,
        (SELECT MIN(expiry_date) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as nearest_expiry,
        (SELECT MIN(sale_price) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as sale_price
        FROM pharmacy LEFT JOIN medicine_category ON medicine_category.id=pharmacy.medicine_category_id
        ORDER BY pharmacy.medicine_name""")
    today_plus30 = (date.today()+timedelta(days=30)).isoformat()
    return render_template('pharmacy/list.html', medicines=rows, today_plus30=today_plus30, today=date.today().isoformat())

@app.route('/pharmacy/add', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_add():
    if request.method == 'POST':
        f = request.form
        mid = edb("INSERT INTO pharmacy (medicine_name,medicine_company,medicine_composition,medicine_category_id,medicine_group,unit,reorder_level) VALUES (?,?,?,?,?,?,?)",
            (f.get('medicine_name'),f.get('medicine_company'),f.get('medicine_composition'),
             f.get('medicine_category_id',1),f.get('medicine_group'),f.get('unit','Tablet'),f.get('reorder_level',10)))
        if f.get('batch_no') or f.get('quantity'):
            edb("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
                (mid,f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),
                 f.get('purchase_price',0),f.get('sale_price',0),f.get('quantity',0)))
        audit('create','pharmacy',mid,f'Medicine {f.get("medicine_name")} added')
        flash('Medicine added successfully.','success')
        return redirect(url_for('pharmacy_list'))
    categories = qdb("SELECT * FROM medicine_category ORDER BY medicine_category")
    return render_template('pharmacy/add.html', categories=categories, today=date.today().isoformat())

@app.route('/pharmacy/<int:mid>/edit', methods=['GET','POST'])
@perm_required('pharmacy','edit')
def pharmacy_edit(mid):
    med = qdb("SELECT * FROM pharmacy WHERE id=?", (mid,), one=True)
    if not med: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("UPDATE pharmacy SET medicine_name=?,medicine_company=?,medicine_composition=?,medicine_category_id=?,medicine_group=?,unit=?,reorder_level=? WHERE id=?",
            (f.get('medicine_name'),f.get('medicine_company'),f.get('medicine_composition'),
             f.get('medicine_category_id',1),f.get('medicine_group'),f.get('unit','Tablet'),f.get('reorder_level',10),mid))
        flash('Medicine updated.','success')
        return redirect(url_for('pharmacy_list'))
    categories = qdb("SELECT * FROM medicine_category ORDER BY medicine_category")
    batches = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? ORDER BY expiry_date", (mid,))
    return render_template('pharmacy/edit.html', med=dict(med), categories=categories, batches=batches)

@app.route('/pharmacy/<int:mid>/stock-in', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_stock_in(mid):
    med = qdb("SELECT * FROM pharmacy WHERE id=?", (mid,), one=True)
    if not med: abort(404)
    if request.method == 'POST':
        f = request.form
        qty = int(f.get('quantity',0))
        pp = float(f.get('purchase_price',0))
        sp = float(f.get('sale_price',0))
        total_cost = qty * pp
        # Add new batch
        batch_id = edb("INSERT INTO medicine_batch_details (pharmacy_id,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,available_quantity) VALUES (?,?,?,?,?,?,?)",
            (mid,f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),pp,sp,qty))
        # Record in purchase log
        edb("INSERT INTO medicine_purchase (pharmacy_id,supplier_name,invoice_no,purchase_date,batch_no,manufacture_date,expiry_date,purchase_price,sale_price,quantity,total_cost,note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid,f.get('supplier_name',''),f.get('invoice_no',''),f.get('purchase_date',date.today().isoformat()),
             f.get('batch_no',''),f.get('manufacture_date',''),f.get('expiry_date',''),pp,sp,qty,total_cost,f.get('note','')))
        audit('stock_in','pharmacy',mid,f'Stock added: {qty} units of {med["medicine_name"]}')
        flash(f'Stock added: {qty} units. Batch {f.get("batch_no","")}.','success')
        return redirect(url_for('pharmacy_list'))
    return render_template('pharmacy/stock_in.html', med=dict(med), today=date.today().isoformat())

@app.route('/pharmacy/dispense', methods=['GET','POST'])
@perm_required('pharmacy','add')
def pharmacy_dispense():
    """Dispense medicines to a patient"""
    if request.method == 'POST':
        f = request.form
        patient_id = int(f.get('patient_id',0))
        items = []
        # Parse multiple medicine items
        med_ids = request.form.getlist('medicine_id')
        batch_ids = request.form.getlist('batch_id')
        quantities = request.form.getlist('quantity')
        notes_list = request.form.getlist('item_note')
        total_bill = 0.0
        for i,mid_str in enumerate(med_ids):
            if not mid_str: continue
            mid = int(mid_str)
            batch_id = int(batch_ids[i]) if i < len(batch_ids) and batch_ids[i] else 0
            qty = int(quantities[i]) if i < len(quantities) and quantities[i] else 1
            # Get batch price
            batch = qdb("SELECT * FROM medicine_batch_details WHERE id=?", (batch_id,), one=True) if batch_id else None
            if not batch:
                batch = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? AND available_quantity>=? ORDER BY expiry_date LIMIT 1", (mid,qty), one=True)
            if not batch:
                flash(f'Insufficient stock for one of the medicines.','danger')
                continue
            sp = float(batch['sale_price'])
            total = sp * qty
            total_bill += total
            # Deduct stock
            edb("UPDATE medicine_batch_details SET available_quantity=available_quantity-? WHERE id=?", (qty,batch['id']))
            # Record dispense
            did = edb("INSERT INTO medicine_dispense (patient_id,pharmacy_id,batch_id,quantity,sale_price,total_amount,dispense_date,dispensed_by,opd_id,ipd_id,note,payment_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (patient_id,mid,batch['id'],qty,sp,total,f.get('dispense_date',date.today().isoformat()),
                 get_user().get('id',0),f.get('opd_id',0),f.get('ipd_id',0),
                 notes_list[i] if i < len(notes_list) else '',f.get('payment_status','paid')))
            items.append(did)
        if items:
            audit('dispense','pharmacy',patient_id,f'Medicines dispensed to patient {patient_id}, total: {total_bill:.2f}')
            flash(f'Medicines dispensed successfully. Total: {get_user().get("currency_symbol","$")}{total_bill:.2f}','success')
        return redirect(url_for('pharmacy_dispense'))
    patients  = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    medicines = qdb("""SELECT pharmacy.*,medicine_category.medicine_category,
        COALESCE((SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id),0) as total_qty,
        (SELECT MIN(sale_price) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id AND available_quantity>0) as sale_price
        FROM pharmacy LEFT JOIN medicine_category ON medicine_category.id=pharmacy.medicine_category_id
        WHERE (SELECT SUM(available_quantity) FROM medicine_batch_details WHERE pharmacy_id=pharmacy.id)>0
        ORDER BY pharmacy.medicine_name""")
    medicines_list = [dict(m) for m in medicines]
    return render_template('pharmacy/dispense.html', patients=patients, medicines=medicines_list, today=date.today().isoformat())

@app.route('/pharmacy/dispense/patient/<int:pid>')
@perm_required('pharmacy','view')
def pharmacy_patient_history(pid):
    """View dispensing history for a patient"""
    patient = qdb("SELECT * FROM patients WHERE id=?", (pid,), one=True)
    records = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,pharmacy.unit,
        staff.name||' '||staff.surname as dispensed_by_name,
        medicine_batch_details.batch_no,medicine_batch_details.expiry_date
        FROM medicine_dispense LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        LEFT JOIN medicine_batch_details ON medicine_batch_details.id=medicine_dispense.batch_id
        WHERE medicine_dispense.patient_id=? ORDER BY medicine_dispense.id DESC""", (pid,))
    return render_template('pharmacy/patient_history.html', patient=dict(patient) if patient else {}, records=records)

@app.route('/pharmacy/purchases')
@perm_required('pharmacy','view')
def pharmacy_purchases():
    rows = qdb("""SELECT medicine_purchase.*,pharmacy.medicine_name FROM medicine_purchase
        JOIN pharmacy ON pharmacy.id=medicine_purchase.pharmacy_id
        ORDER BY medicine_purchase.id DESC LIMIT 200""")
    return render_template('pharmacy/purchases.html', records=rows)

@app.route('/pharmacy/dispense/all')
@perm_required('pharmacy','view')
def pharmacy_dispense_all():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,pharmacy.unit,
        patients.patient_name,patients.patient_unique_id,
        staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense LEFT JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        LEFT JOIN patients ON patients.id=medicine_dispense.patient_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.dispense_date=? ORDER BY medicine_dispense.id DESC""", (date_filter,))
    total = sum(float(r['total_amount'] or 0) for r in rows)
    return render_template('pharmacy/dispense_all.html', records=rows, date_filter=date_filter, total=total)

@app.route('/pharmacy/<int:mid>/batches')
@perm_required('pharmacy','view')
def pharmacy_batches(mid):
    """Ajax: get available batches for a medicine"""
    batches = qdb("SELECT * FROM medicine_batch_details WHERE pharmacy_id=? AND available_quantity>0 ORDER BY expiry_date", (mid,))
    return jsonify([dict(b) for b in batches])

@app.route('/pharmacy/<int:mid>/delete', methods=['POST'])
@perm_required('pharmacy','delete')
def pharmacy_delete(mid):
    edb("DELETE FROM pharmacy WHERE id=?", (mid,))
    flash('Medicine deleted.','success')
    return redirect(url_for('pharmacy_list'))


# ─────────────────────────────────────────────
# STAFF & USER MANAGEMENT
# ─────────────────────────────────────────────
@app.route('/staff')
@perm_required('staff','view')
def staff_list():
    rows = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,staff_designation.designation as designation_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.is_active=1 ORDER BY staff.employee_id""")
    return render_template('staff/list.html', staff_list=rows)

@app.route('/staff/add', methods=['GET','POST'])
@perm_required('staff','add')
def staff_add():
    if request.method == 'POST':
        f = request.form
        # Generate employee ID
        count = qdb("SELECT COUNT(*) as c FROM staff", one=True)['c']
        emp_id = f'EMP{count+1:04d}'
        # Check if email exists
        existing = qdb("SELECT id FROM staff WHERE email=?", (f.get('email',''),), one=True)
        if existing:
            flash('Email already exists. Please use a different email.','danger')
            roles = qdb("SELECT * FROM roles WHERE is_active=1")
            departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
            designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
            return render_template('staff/add.html', roles=roles, departments=departments, designations=designations)
        sid = edb("""INSERT INTO staff (employee_id,name,surname,email,password,phone,mobileno,gender,dob,blood_group,
            date_of_joining,address,department,designation,qualification,experience,basic_salary,bank_name,bank_account,emergency_contact,note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (emp_id,f.get('name'),f.get('surname'),f.get('email'),hash_pw(f.get('password','admin123')),
             f.get('phone'),f.get('mobileno'),f.get('gender'),f.get('dob',''),f.get('blood_group',''),
             f.get('date_of_joining',date.today().isoformat()),f.get('address'),
             f.get('department',0),f.get('designation',0),f.get('qualification'),f.get('experience'),
             f.get('basic_salary',0),f.get('bank_name'),f.get('bank_account'),f.get('emergency_contact'),f.get('note','')))
        # Assign role
        role_id = f.get('role_id',0)
        if role_id:
            edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
        audit('create','staff',sid,f'Staff {f.get("name")} {f.get("surname")} created (Emp:{emp_id})')
        flash(f'Staff member created. Employee ID: {emp_id} | Login: {f.get("email")} | Password: {f.get("password","admin123")}','success')
        return redirect(url_for('staff_list'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
    return render_template('staff/add.html', roles=roles, departments=departments, designations=designations, today=date.today().isoformat())

@app.route('/staff/<int:sid>/view')
@perm_required('staff','view')
def staff_view(sid):
    member = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,staff_designation.designation as designation_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.id=?""", (sid,), one=True)
    if not member: abort(404)
    attendance  = qdb("SELECT * FROM attendance WHERE staff_id=? ORDER BY date DESC LIMIT 30", (sid,))
    leaves      = qdb("SELECT leave_applications.*,leave_types.name as leave_name FROM leave_applications JOIN leave_types ON leave_types.id=leave_applications.leave_type_id WHERE staff_id=? ORDER BY id DESC", (sid,))
    appraisals  = qdb("SELECT * FROM performance_appraisal WHERE staff_id=? ORDER BY id DESC", (sid,))
    trainings   = qdb("SELECT training.*,training_participants.status as enroll_status,training_participants.score FROM training JOIN training_participants ON training_participants.training_id=training.id WHERE training_participants.staff_id=?", (sid,))
    payrolls    = qdb("SELECT * FROM payroll WHERE staff_id=? ORDER BY year DESC,id DESC LIMIT 12", (sid,))
    return render_template('staff/view.html', member=dict(member), attendance=attendance, leaves=leaves, appraisals=appraisals, trainings=trainings, payrolls=payrolls)

@app.route('/staff/<int:sid>/edit', methods=['GET','POST'])
@perm_required('staff','edit')
def staff_edit(sid):
    member = qdb("SELECT * FROM staff WHERE id=?", (sid,), one=True)
    if not member: abort(404)
    if request.method == 'POST':
        f = request.form
        edb("""UPDATE staff SET name=?,surname=?,email=?,phone=?,mobileno=?,gender=?,dob=?,
            date_of_joining=?,address=?,department=?,designation=?,qualification=?,experience=?,note=?,
            basic_salary=?,bank_name=?,bank_account=?,emergency_contact=?,blood_group=? WHERE id=?""",
            (f.get('name'),f.get('surname'),f.get('email'),f.get('phone'),f.get('mobileno'),
             f.get('gender'),f.get('dob'),f.get('date_of_joining'),f.get('address'),
             f.get('department',0),f.get('designation',0),f.get('qualification'),
             f.get('experience'),f.get('note'),f.get('basic_salary',0),f.get('bank_name'),
             f.get('bank_account'),f.get('emergency_contact'),f.get('blood_group'),sid))
        # Update role
        role_id = f.get('role_id')
        if role_id:
            edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,int(role_id)))
        # Update password if provided
        new_pw = f.get('new_password','').strip()
        if new_pw:
            edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),sid))
            flash(f'Password updated.','info')
        audit('update','staff',sid,'Staff profile updated')
        flash('Staff updated.','success')
        return redirect(url_for('staff_list'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    designations = qdb("SELECT * FROM staff_designation ORDER BY designation")
    current_role = qdb("SELECT role_id FROM staff_roles WHERE staff_id=?", (sid,), one=True)
    return render_template('staff/edit.html', member=dict(member), roles=roles, departments=departments, designations=designations, current_role_id=current_role['role_id'] if current_role else 0)

@app.route('/staff/<int:sid>/reset-password', methods=['POST'])
@perm_required('staff','edit')
def staff_reset_password(sid):
    new_pw = request.form.get('new_password','admin123')
    edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),sid))
    audit('reset_password','staff',sid,'Password reset')
    flash(f'Password reset to: {new_pw}','success')
    return redirect(url_for('staff_view',sid=sid))

@app.route('/staff/<int:sid>/delete', methods=['POST'])
@perm_required('staff','delete')
def staff_delete(sid):
    edb("UPDATE staff SET is_active=0 WHERE id=?", (sid,))
    flash('Staff deactivated.','success')
    return redirect(url_for('staff_list'))

# ─────────────────────────────────────────────
# PAYROLL
# ─────────────────────────────────────────────
@app.route('/payroll')
@perm_required('payroll','view')
def payroll_list():
    rows = qdb("SELECT payroll.*,staff.name,staff.surname,staff.employee_id FROM payroll JOIN staff ON staff.id=payroll.staff_id ORDER BY payroll.id DESC")
    return render_template('payroll/list.html', records=rows)

@app.route('/payroll/add', methods=['GET','POST'])
@perm_required('payroll','add')
def payroll_add():
    if request.method == 'POST':
        f = request.form
        basic = float(f.get('basic_salary',0)); allow = float(f.get('allowances',0)); deduct = float(f.get('deductions',0))
        net = basic + allow - deduct
        edb("INSERT INTO payroll (staff_id,month,year,basic_salary,allowances,deductions,net_salary,payment_status,note) VALUES (?,?,?,?,?,?,?,?,?)",
            (f.get('staff_id'),f.get('month'),f.get('year',date.today().year),basic,allow,deduct,net,f.get('payment_status','unpaid'),f.get('note','')))
        flash('Payroll record added.','success')
        return redirect(url_for('payroll_list'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    months = ['January','February','March','April','May','June','July','August','September','October','November','December']
    return render_template('payroll/add.html', staff=staff, months=months, current_year=date.today().year)

@app.route('/payroll/<int:pid>/mark_paid', methods=['POST'])
@perm_required('payroll','edit')
def payroll_mark_paid(pid):
    edb("UPDATE payroll SET payment_status='paid',payment_date=? WHERE id=?", (date.today().isoformat(),pid))
    flash('Marked as paid.','success')
    return redirect(url_for('payroll_list'))

# ─────────────────────────────────────────────
# HR — LEAVE
# ─────────────────────────────────────────────
@app.route('/hr/leave')
@perm_required('hr_leave','view')
def hr_leave():
    rows = qdb("""SELECT leave_applications.*,staff.name,staff.surname,staff.employee_id,leave_types.name as leave_name
        FROM leave_applications JOIN staff ON staff.id=leave_applications.staff_id
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        ORDER BY leave_applications.id DESC""")
    leave_types = qdb("SELECT * FROM leave_types WHERE is_active=1")
    return render_template('hr/leave.html', records=rows, leave_types=leave_types)

@app.route('/hr/leave/add', methods=['GET','POST'])
@perm_required('hr_leave','add')
def hr_leave_add():
    if request.method == 'POST':
        f = request.form
        from_d = date.fromisoformat(f.get('from_date',date.today().isoformat()))
        to_d   = date.fromisoformat(f.get('to_date',date.today().isoformat()))
        days   = (to_d - from_d).days + 1
        edb("INSERT INTO leave_applications (staff_id,leave_type_id,from_date,to_date,total_days,reason) VALUES (?,?,?,?,?,?)",
            (f.get('staff_id'),f.get('leave_type_id'),f.get('from_date'),f.get('to_date'),days,f.get('reason','')))
        flash('Leave application submitted.','success')
        return redirect(url_for('hr_leave'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    leave_types = qdb("SELECT * FROM leave_types WHERE is_active=1")
    return render_template('hr/leave_add.html', staff=staff, leave_types=leave_types, today=date.today().isoformat())

@app.route('/hr/leave/<int:lid>/approve', methods=['POST'])
@perm_required('hr_leave','edit')
def hr_leave_approve(lid):
    status = request.form.get('status','approved')
    edb("UPDATE leave_applications SET status=?,approved_by=?,approved_date=? WHERE id=?",
        (status, get_user().get('id',0), date.today().isoformat(), lid))
    flash(f'Leave {status}.','success')
    return redirect(url_for('hr_leave'))

# ─────────────────────────────────────────────
# HR — ATTENDANCE
# ─────────────────────────────────────────────
@app.route('/hr/attendance')
@perm_required('hr_attendance','view')
def hr_attendance():
    date_filter = request.args.get('date', date.today().isoformat())
    rows = qdb("SELECT attendance.*,staff.name,staff.surname,staff.employee_id FROM attendance JOIN staff ON staff.id=attendance.staff_id WHERE attendance.date=? ORDER BY staff.employee_id", (date_filter,))
    all_staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY employee_id")
    # Build dict of marked records
    marked = {r['staff_id']: dict(r) for r in rows}
    return render_template('hr/attendance.html', records=rows, all_staff=all_staff, date_filter=date_filter, marked=marked)

@app.route('/hr/attendance/mark', methods=['POST'])
@perm_required('hr_attendance','add')
def hr_attendance_mark():
    date_val = request.form.get('date', date.today().isoformat())
    staff_ids = request.form.getlist('staff_id')
    statuses  = request.form.getlist('status')
    for i,sid in enumerate(staff_ids):
        st = statuses[i] if i < len(statuses) else 'present'
        tin  = request.form.get(f'time_in_{sid}','09:00')
        tout = request.form.get(f'time_out_{sid}','17:00')
        edb("INSERT OR REPLACE INTO attendance (staff_id,date,status,time_in,time_out) VALUES (?,?,?,?,?)", (sid,date_val,st,tin,tout))
    flash('Attendance saved.','success')
    return redirect(url_for('hr_attendance',date=date_val))

@app.route('/hr/attendance/report')
@perm_required('hr_attendance','view')
def hr_attendance_report():
    month = request.args.get('month', date.today().strftime('%Y-%m'))
    rows = qdb("""SELECT staff.id,staff.employee_id,staff.name,staff.surname,
        SUM(CASE WHEN attendance.status='present' THEN 1 ELSE 0 END) as present_days,
        SUM(CASE WHEN attendance.status='absent' THEN 1 ELSE 0 END) as absent_days,
        SUM(CASE WHEN attendance.status='late' THEN 1 ELSE 0 END) as late_days,
        SUM(CASE WHEN attendance.status='half_day' THEN 1 ELSE 0 END) as half_days,
        COUNT(attendance.id) as total_marked
        FROM staff LEFT JOIN attendance ON attendance.staff_id=staff.id AND strftime('%Y-%m',attendance.date)=?
        WHERE staff.is_active=1 GROUP BY staff.id ORDER BY staff.employee_id""", (month,))
    return render_template('hr/attendance_report.html', records=rows, month=month)

# ─────────────────────────────────────────────
# HR — APPRAISAL
# ─────────────────────────────────────────────
@app.route('/hr/appraisal')
@perm_required('hr_appraisal','view')
def hr_appraisal():
    rows = qdb("""SELECT performance_appraisal.*,staff.name,staff.surname,staff.employee_id,
        s2.name||' '||s2.surname as reviewer_name
        FROM performance_appraisal JOIN staff ON staff.id=performance_appraisal.staff_id
        LEFT JOIN staff s2 ON s2.id=performance_appraisal.reviewer_id
        ORDER BY performance_appraisal.id DESC""")
    return render_template('hr/appraisal.html', records=rows)

@app.route('/hr/appraisal/add', methods=['GET','POST'])
@perm_required('hr_appraisal','add')
def hr_appraisal_add():
    if request.method == 'POST':
        f = request.form
        scores = [int(f.get(k,0)) for k in ['punctuality','teamwork','technical_skills','communication','patient_care']]
        overall = sum(scores)/5
        grade = 'A+' if overall>=90 else 'A' if overall>=80 else 'B' if overall>=70 else 'C' if overall>=60 else 'D'
        edb("""INSERT INTO performance_appraisal (staff_id,period,reviewer_id,punctuality,teamwork,technical_skills,communication,patient_care,overall_score,grade,strengths,improvements,goals,reviewer_comments,status,review_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (f.get('staff_id'),f.get('period'),get_user().get('id',0),*scores,overall,grade,
             f.get('strengths',''),f.get('improvements',''),f.get('goals',''),f.get('reviewer_comments',''),f.get('status','draft'),date.today().isoformat()))
        flash('Appraisal saved.','success')
        return redirect(url_for('hr_appraisal'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    periods = [f'Q{q} {y}' for y in [date.today().year, date.today().year-1] for q in [1,2,3,4]]
    periods += [f'Annual {y}' for y in [date.today().year, date.today().year-1]]
    return render_template('hr/appraisal_add.html', staff=staff, periods=periods)

# ─────────────────────────────────────────────
# HR — TRAINING
# ─────────────────────────────────────────────
@app.route('/hr/training')
@perm_required('hr_training','view')
def hr_training():
    rows = qdb("""SELECT training.*,COUNT(training_participants.id) as enrolled_count
        FROM training LEFT JOIN training_participants ON training_participants.training_id=training.id
        GROUP BY training.id ORDER BY training.id DESC""")
    return render_template('hr/training.html', records=rows)

@app.route('/hr/training/add', methods=['GET','POST'])
@perm_required('hr_training','add')
def hr_training_add():
    if request.method == 'POST':
        f = request.form
        tid = edb("INSERT INTO training (title,category,trainer,start_date,end_date,duration_hours,location,description) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('title'),f.get('category'),f.get('trainer'),f.get('start_date'),f.get('end_date'),f.get('duration_hours',0),f.get('location'),f.get('description','')))
        for sid in request.form.getlist('participants'):
            edb("INSERT OR IGNORE INTO training_participants (training_id,staff_id) VALUES (?,?)", (tid,sid))
        flash('Training program created.','success')
        return redirect(url_for('hr_training'))
    staff = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    categories = ['Clinical','Safety','Administrative','Technical','Soft Skills','Compliance','Other']
    return render_template('hr/training_add.html', staff=staff, categories=categories, today=date.today().isoformat())

@app.route('/hr/training/<int:tid>')
@perm_required('hr_training','view')
def hr_training_view(tid):
    training = qdb("SELECT * FROM training WHERE id=?", (tid,), one=True)
    participants = qdb("""SELECT training_participants.*,staff.name,staff.surname,staff.employee_id
        FROM training_participants JOIN staff ON staff.id=training_participants.staff_id
        WHERE training_participants.training_id=?""", (tid,))
    return render_template('hr/training_view.html', training=dict(training) if training else {}, participants=participants)

@app.route('/hr/training/<int:tid>/complete/<int:sid>', methods=['POST'])
@perm_required('hr_training','edit')
def hr_training_complete(tid, sid):
    score = request.form.get('score',0)
    cert  = 1 if request.form.get('certificate') else 0
    edb("UPDATE training_participants SET status='completed',score=?,certificate_issued=?,completion_date=? WHERE training_id=? AND staff_id=?",
        (score,cert,date.today().isoformat(),tid,sid))
    flash('Training marked as completed.','success')
    return redirect(url_for('hr_training_view',tid=tid))


# ─────────────────────────────────────────────
# BLOOD BANK
# ─────────────────────────────────────────────
@app.route('/bloodbank')
@perm_required('bloodbank','view')
def bloodbank():
    inventory  = qdb("SELECT * FROM blood_inventory ORDER BY blood_group")
    donations  = qdb("SELECT * FROM blood_donations ORDER BY id DESC LIMIT 50")
    requests   = qdb("""SELECT blood_requests.*,patients.patient_name FROM blood_requests
        LEFT JOIN patients ON patients.id=blood_requests.patient_id ORDER BY blood_requests.id DESC LIMIT 50""")
    return render_template('bloodbank/index.html', inventory=inventory, donations=donations, requests=requests)

@app.route('/bloodbank/donate', methods=['GET','POST'])
@perm_required('bloodbank','add')
def bloodbank_donate():
    if request.method == 'POST':
        f = request.form
        bg = f.get('blood_group')
        units = int(f.get('units_donated',1))
        edb("INSERT INTO blood_donations (donor_name,blood_group,donor_contact,donor_age,donation_date,units_donated,expiry_date,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('donor_name'),bg,f.get('donor_contact'),f.get('donor_age',0),f.get('donation_date'),units,f.get('expiry_date',''),f.get('note','')))
        edb("INSERT OR IGNORE INTO blood_inventory (blood_group,units_available) VALUES (?,0)", (bg,))
        edb("UPDATE blood_inventory SET units_available=units_available+?,last_updated=CURRENT_TIMESTAMP WHERE blood_group=?", (units,bg))
        flash('Donation recorded and inventory updated.','success')
        return redirect(url_for('bloodbank'))
    blood_groups = ['A+','A-','B+','B-','AB+','AB-','O+','O-']
    return render_template('bloodbank/donate.html', blood_groups=blood_groups, today=date.today().isoformat())

@app.route('/bloodbank/request', methods=['GET','POST'])
@perm_required('bloodbank','add')
def bloodbank_request():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO blood_requests (patient_id,blood_group,units_required,required_date,doctor_id,purpose,note) VALUES (?,?,?,?,?,?,?)",
            (f.get('patient_id',0),f.get('blood_group'),f.get('units_required',1),f.get('required_date',''),f.get('doctor_id',0),f.get('purpose',''),f.get('note','')))
        flash('Blood request submitted.','success')
        return redirect(url_for('bloodbank'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    doctors  = qdb("SELECT * FROM staff WHERE is_active=1 ORDER BY name")
    inventory = {r['blood_group']:r['units_available'] for r in qdb("SELECT * FROM blood_inventory")}
    blood_groups = ['A+','A-','B+','B-','AB+','AB-','O+','O-']
    return render_template('bloodbank/request.html', patients=patients, doctors=doctors, inventory=inventory, blood_groups=blood_groups)

@app.route('/bloodbank/request/<int:rid>/approve', methods=['POST'])
@perm_required('bloodbank','edit')
def bloodbank_approve(rid):
    req = qdb("SELECT * FROM blood_requests WHERE id=?", (rid,), one=True)
    if req:
        inv = qdb("SELECT * FROM blood_inventory WHERE blood_group=?", (req['blood_group'],), one=True)
        if inv and inv['units_available'] >= req['units_required']:
            edb("UPDATE blood_requests SET status='approved' WHERE id=?", (rid,))
            edb("UPDATE blood_inventory SET units_available=units_available-?,last_updated=CURRENT_TIMESTAMP WHERE blood_group=?", (req['units_required'],req['blood_group']))
            flash('Request approved and inventory updated.','success')
        else:
            edb("UPDATE blood_requests SET status='approved' WHERE id=?", (rid,))
            flash('Request approved (insufficient stock — please arrange externally).','warning')
    return redirect(url_for('bloodbank'))

# ─────────────────────────────────────────────
# INSURANCE / TPA
# ─────────────────────────────────────────────
@app.route('/insurance')
@perm_required('insurance','view')
def insurance():
    tpa_list = qdb("SELECT * FROM tpa ORDER BY organisation_name")
    return render_template('insurance/list.html', tpa_list=tpa_list)

@app.route('/insurance/add', methods=['GET','POST'])
@perm_required('insurance','add')
def insurance_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO tpa (organisation_name,contact_person,email,phone,address,coverage_limit,policy_details) VALUES (?,?,?,?,?,?,?)",
            (f.get('organisation_name'),f.get('contact_person'),f.get('email'),f.get('phone'),f.get('address'),f.get('coverage_limit',0),f.get('policy_details','')))
        flash('TPA added.','success')
        return redirect(url_for('insurance'))
    return render_template('insurance/add.html')

@app.route('/insurance/<int:tid>/toggle', methods=['POST'])
@perm_required('insurance','edit')
def insurance_toggle(tid):
    tpa = qdb("SELECT is_active FROM tpa WHERE id=?", (tid,), one=True)
    if tpa:
        edb("UPDATE tpa SET is_active=? WHERE id=?", (0 if tpa['is_active'] else 1, tid))
    flash('Status updated.','success')
    return redirect(url_for('insurance'))

# ─────────────────────────────────────────────
# VEHICLE / AMBULANCE
# ─────────────────────────────────────────────
@app.route('/vehicle')
@perm_required('vehicle','view')
def vehicle_list():
    vehicles = qdb("SELECT * FROM vehicle ORDER BY vehicle_name")
    trips    = qdb("""SELECT vehicle_trips.*,vehicle.vehicle_name,patients.patient_name
        FROM vehicle_trips LEFT JOIN vehicle ON vehicle.id=vehicle_trips.vehicle_id
        LEFT JOIN patients ON patients.id=vehicle_trips.patient_id
        ORDER BY vehicle_trips.id DESC LIMIT 50""")
    return render_template('vehicle/list.html', vehicles=vehicles, trips=trips)

@app.route('/vehicle/add', methods=['GET','POST'])
@perm_required('vehicle','add')
def vehicle_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO vehicle (vehicle_name,vehicle_number,vehicle_type,driver_name,driver_phone,fuel_type) VALUES (?,?,?,?,?,?)",
            (f.get('vehicle_name'),f.get('vehicle_number'),f.get('vehicle_type','ambulance'),f.get('driver_name'),f.get('driver_phone'),f.get('fuel_type','Diesel')))
        flash('Vehicle added.','success')
        return redirect(url_for('vehicle_list'))
    return render_template('vehicle/add.html')

@app.route('/vehicle/trip', methods=['GET','POST'])
@perm_required('vehicle','add')
def vehicle_trip():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO vehicle_trips (vehicle_id,patient_id,trip_date,pickup_location,drop_location,distance_km,charge,note) VALUES (?,?,?,?,?,?,?,?)",
            (f.get('vehicle_id'),f.get('patient_id',0),f.get('trip_date',date.today().isoformat()),
             f.get('pickup_location'),f.get('drop_location'),f.get('distance_km',0),f.get('charge',0),f.get('note','')))
        flash('Trip logged.','success')
        return redirect(url_for('vehicle_list'))
    vehicles = qdb("SELECT * FROM vehicle ORDER BY vehicle_name")
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    return render_template('vehicle/trip.html', vehicles=vehicles, patients=patients, today=date.today().isoformat())

# ─────────────────────────────────────────────
# VISITORS
# ─────────────────────────────────────────────
@app.route('/visitors')
@perm_required('visitors','view')
def visitors_list():
    visitors = qdb("""SELECT visitors.*,patients.patient_name FROM visitors
        LEFT JOIN patients ON patients.id=visitors.patient_id
        ORDER BY visitors.id DESC LIMIT 100""")
    return render_template('visitors/list.html', visitors=visitors)

@app.route('/visitors/add', methods=['GET','POST'])
@perm_required('visitors','add')
def visitor_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO visitors (visitor_name,patient_id,purpose,visit_date,visit_time,note) VALUES (?,?,?,?,?,?)",
            (f.get('visitor_name'),f.get('patient_id',0),f.get('purpose'),f.get('visit_date'),f.get('visit_time',''),f.get('note','')))
        flash('Visitor registered.','success')
        return redirect(url_for('visitors_list'))
    patients = qdb("SELECT * FROM patients WHERE is_active=1 ORDER BY patient_name")
    return render_template('visitors/add.html', patients=patients, today=date.today().isoformat())

# ─────────────────────────────────────────────
# INCOME
# ─────────────────────────────────────────────
@app.route('/income')
@perm_required('income','view')
def income_list():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    rows  = qdb("SELECT income.*,income_head.income_category FROM income LEFT JOIN income_head ON income_head.id=income.income_head_id WHERE income.date BETWEEN ? AND ? ORDER BY income.date DESC",(start,end))
    total = sum(float(r['amount'] or 0) for r in rows)
    heads = qdb("SELECT * FROM income_head")
    return render_template('income/list.html', records=rows, total=total, start=start, end=end, heads=heads)

@app.route('/income/add', methods=['GET','POST'])
@perm_required('income','add')
def income_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO income (name,income_head_id,invoice_no,amount,date,note) VALUES (?,?,?,?,?,?)",
            (f.get('name'),f.get('income_head_id',0),f.get('invoice_no'),f.get('amount',0),f.get('date'),f.get('note','')))
        flash('Income recorded.','success')
        return redirect(url_for('income_list'))
    heads = qdb("SELECT * FROM income_head")
    return render_template('income/add.html', heads=heads, today=date.today().isoformat())

@app.route('/income/<int:iid>/delete', methods=['POST'])
@perm_required('income','delete')
def income_delete(iid):
    edb("DELETE FROM income WHERE id=?", (iid,))
    flash('Income record deleted.','success')
    return redirect(url_for('income_list'))

# ─────────────────────────────────────────────
# EXPENSES
# ─────────────────────────────────────────────
@app.route('/expenses')
@perm_required('expenses','view')
def expenses_list():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    rows  = qdb("SELECT expenses.*,expense_head.exp_category FROM expenses LEFT JOIN expense_head ON expense_head.id=expenses.exp_head_id WHERE expenses.date BETWEEN ? AND ? ORDER BY expenses.date DESC",(start,end))
    total = sum(float(r['amount'] or 0) for r in rows)
    heads = qdb("SELECT * FROM expense_head")
    return render_template('expenses/list.html', records=rows, total=total, start=start, end=end, heads=heads)

@app.route('/expenses/add', methods=['GET','POST'])
@perm_required('expenses','add')
def expense_add():
    if request.method == 'POST':
        f = request.form
        edb("INSERT INTO expenses (name,exp_head_id,invoice_no,amount,date,note) VALUES (?,?,?,?,?,?)",
            (f.get('name'),f.get('exp_head_id',0),f.get('invoice_no'),f.get('amount',0),f.get('date'),f.get('note','')))
        flash('Expense recorded.','success')
        return redirect(url_for('expenses_list'))
    heads = qdb("SELECT * FROM expense_head")
    return render_template('expenses/add.html', heads=heads, today=date.today().isoformat())

@app.route('/expenses/<int:eid>/delete', methods=['POST'])
@perm_required('expenses','delete')
def expense_delete(eid):
    edb("DELETE FROM expenses WHERE id=?", (eid,))
    flash('Expense record deleted.','success')
    return redirect(url_for('expenses_list'))

# ─────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────
@app.route('/reports')
@perm_required('reports','view')
def reports():
    return render_template('reports/index.html')

@app.route('/reports/financial')
@perm_required('reports','view')
def report_financial():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    total_income  = qdb("SELECT COALESCE(SUM(amount),0) as s FROM income WHERE date BETWEEN ? AND ?",(start,end),one=True)['s']
    total_expense = qdb("SELECT COALESCE(SUM(amount),0) as s FROM expenses WHERE date BETWEEN ? AND ?",(start,end),one=True)['s']
    income_by_head  = qdb("SELECT income_head.income_category,COALESCE(SUM(income.amount),0) as total FROM income_head LEFT JOIN income ON income.income_head_id=income_head.id AND income.date BETWEEN ? AND ? GROUP BY income_head.id",(start,end))
    expense_by_head = qdb("SELECT expense_head.exp_category,COALESCE(SUM(expenses.amount),0) as total FROM expense_head LEFT JOIN expenses ON expenses.exp_head_id=expense_head.id AND expenses.date BETWEEN ? AND ? GROUP BY expense_head.id",(start,end))
    return render_template('reports/financial.html', total_income=total_income, total_expense=total_expense,
                           profit=total_income-total_expense, income_by_head=income_by_head,
                           expense_by_head=expense_by_head, start=start, end=end)

@app.route('/reports/patients')
@perm_required('reports','view')
def report_patients():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    opd = qdb("""SELECT opd_details.*,patients.patient_name,patients.gender,staff.name||' '||staff.surname as doctor_name
        FROM opd_details JOIN patients ON patients.id=opd_details.patient_id
        LEFT JOIN staff ON staff.id=opd_details.doctor_id
        WHERE opd_details.date BETWEEN ? AND ? ORDER BY opd_details.date DESC""",(start,end))
    ipd = qdb("""SELECT ipd_details.*,patients.patient_name,patients.gender,staff.name||' '||staff.surname as doctor_name,bed.bed_name
        FROM ipd_details JOIN patients ON patients.id=ipd_details.patient_id
        LEFT JOIN staff ON staff.id=ipd_details.doctor_id LEFT JOIN bed ON bed.id=ipd_details.bed
        WHERE ipd_details.date BETWEEN ? AND ? ORDER BY ipd_details.date DESC""",(start,end))
    return render_template('reports/patients.html', opd=opd, ipd=ipd, start=start, end=end)

@app.route('/reports/hr')
@perm_required('reports','view')
def report_hr():
    month = request.args.get('month', date.today().strftime('%Y-%m'))
    payroll_summary = qdb("SELECT COUNT(*) as count,SUM(net_salary) as total_payroll,SUM(CASE WHEN payment_status='paid' THEN 1 ELSE 0 END) as paid_count FROM payroll WHERE month=? AND year=?",
                          (datetime.strptime(month,'%Y-%m').strftime('%B'),int(month[:4])), one=True)
    leave_summary = qdb("""SELECT leave_types.name,COUNT(leave_applications.id) as count,
        SUM(CASE WHEN leave_applications.status='approved' THEN 1 ELSE 0 END) as approved,
        SUM(leave_applications.total_days) as total_days
        FROM leave_types LEFT JOIN leave_applications ON leave_applications.leave_type_id=leave_types.id
        GROUP BY leave_types.id""")
    dept_attendance = qdb("""SELECT department.department_name,
        SUM(CASE WHEN attendance.status='present' THEN 1 ELSE 0 END) as present,
        SUM(CASE WHEN attendance.status='absent' THEN 1 ELSE 0 END) as absent
        FROM department LEFT JOIN staff ON staff.department=department.id
        LEFT JOIN attendance ON attendance.staff_id=staff.id AND strftime('%Y-%m',attendance.date)=?
        WHERE staff.is_active=1 GROUP BY department.id ORDER BY department.department_name""",(month,))
    return render_template('reports/hr.html', payroll_summary=payroll_summary, leave_summary=leave_summary, dept_attendance=dept_attendance, month=month)

@app.route('/reports/pharmacy')
@perm_required('reports','view')
def report_pharmacy():
    start = request.args.get('start',(date.today()-timedelta(days=30)).isoformat())
    end   = request.args.get('end',date.today().isoformat())
    dispenses = qdb("""SELECT medicine_dispense.*,pharmacy.medicine_name,patients.patient_name,
        staff.name||' '||staff.surname as dispensed_by_name
        FROM medicine_dispense JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        JOIN patients ON patients.id=medicine_dispense.patient_id
        LEFT JOIN staff ON staff.id=medicine_dispense.dispensed_by
        WHERE medicine_dispense.dispense_date BETWEEN ? AND ? ORDER BY medicine_dispense.id DESC""",(start,end))
    total_revenue = sum(float(r['total_amount'] or 0) for r in dispenses)
    top_medicines = qdb("""SELECT pharmacy.medicine_name,SUM(medicine_dispense.quantity) as total_qty,
        SUM(medicine_dispense.total_amount) as total_revenue
        FROM medicine_dispense JOIN pharmacy ON pharmacy.id=medicine_dispense.pharmacy_id
        WHERE medicine_dispense.dispense_date BETWEEN ? AND ?
        GROUP BY medicine_dispense.pharmacy_id ORDER BY total_revenue DESC LIMIT 10""",(start,end))
    return render_template('reports/pharmacy.html', dispenses=dispenses, total_revenue=total_revenue, top_medicines=top_medicines, start=start, end=end)


# ─────────────────────────────────────────────
# ADMIN PANEL — Full user & role management
# ─────────────────────────────────────────────
@app.route('/admin')
@perm_required('admin','view')
def admin():
    stats = {
        'total_users': qdb("SELECT COUNT(*) as c FROM staff WHERE is_active=1", one=True)['c'],
        'total_roles':  qdb("SELECT COUNT(*) as c FROM roles", one=True)['c'],
        'today_logins': qdb("SELECT COUNT(*) as c FROM userlog WHERE action='login' AND date(created_at)=?", (date.today().isoformat(),), one=True)['c'],
        'total_actions': qdb("SELECT COUNT(*) as c FROM audit_log", one=True)['c'],
    }
    roles = qdb("SELECT roles.*,COUNT(staff_roles.staff_id) as staff_count FROM roles LEFT JOIN staff_roles ON staff_roles.role_id=roles.id GROUP BY roles.id")
    user_logs = qdb("SELECT userlog.*,staff.name,staff.surname,roles.name as role FROM userlog LEFT JOIN staff ON staff.id=userlog.staff_id LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id LEFT JOIN roles ON roles.id=staff_roles.role_id ORDER BY userlog.id DESC LIMIT 20")
    recent_logs = qdb("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15")
    return render_template('admin/panel.html', stats=stats, roles=roles, user_logs=user_logs, recent_logs=recent_logs)

@app.route('/admin/roles')
@perm_required('admin','view')
def admin_roles():
    roles = qdb("SELECT roles.*,COUNT(staff_roles.staff_id) as staff_count FROM roles LEFT JOIN staff_roles ON staff_roles.role_id=roles.id GROUP BY roles.id ORDER BY roles.id")
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/add', methods=['GET','POST'])
@perm_required('admin','add')
def admin_role_add():
    if request.method == 'POST':
        f = request.form
        rid = edb("INSERT INTO roles (name,description) VALUES (?,?)", (f.get('name'),f.get('description','')))
        for mod in ALL_MODULES:
            v=1 if f.get(f'{mod}_view') else 0; a=1 if f.get(f'{mod}_add') else 0
            e=1 if f.get(f'{mod}_edit') else 0; d=1 if f.get(f'{mod}_delete') else 0
            edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",(rid,mod,v,a,e,d))
        audit('create','admin',rid,f'Role {f.get("name")} created')
        flash('Role created.','success')
        return redirect(url_for('admin_roles'))
    return render_template('admin/role_add.html', modules=ALL_MODULES)

@app.route('/admin/roles/<int:rid>/permissions', methods=['GET','POST'])
@perm_required('admin','edit')
def admin_role_permissions(rid):
    role = qdb("SELECT * FROM roles WHERE id=?", (rid,), one=True)
    if not role: abort(404)
    if request.method == 'POST':
        for mod in ALL_MODULES:
            v=1 if request.form.get(f'{mod}_view') else 0; a=1 if request.form.get(f'{mod}_add') else 0
            e=1 if request.form.get(f'{mod}_edit') else 0; d=1 if request.form.get(f'{mod}_delete') else 0
            edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",(rid,mod,v,a,e,d))
        audit('update','admin',rid,f'Permissions updated for role {role["name"]}')
        flash('Permissions saved.','success')
        return redirect(url_for('admin_roles'))
    rows = qdb("SELECT * FROM role_permissions WHERE role_id=?", (rid,))
    perms = {r['module']: {'view':bool(r['can_view']),'add':bool(r['can_add']),'edit':bool(r['can_edit']),'delete':bool(r['can_delete'])} for r in rows}
    return render_template('admin/role_permissions.html', role=dict(role), perms=perms, modules=ALL_MODULES)

@app.route('/admin/users')
@perm_required('admin','view')
def admin_users():
    users = qdb("""SELECT staff.*,roles.name as role_name,department.department_name
        FROM staff LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        ORDER BY staff.employee_id""")
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET','POST'])
@perm_required('admin','add')
def admin_user_create():
    """Create a new user with role and module access"""
    if request.method == 'POST':
        f = request.form
        # Check email unique
        existing = qdb("SELECT id FROM staff WHERE email=?", (f.get('email',''),), one=True)
        if existing:
            flash('Email already in use.','danger')
            roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
            departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
            return render_template('admin/user_create.html', roles=roles, departments=departments)
        count = qdb("SELECT COUNT(*) as c FROM staff", one=True)['c']
        emp_id = f.get('employee_id','').strip() or f'EMP{count+1:04d}'
        pw_raw = f.get('password','admin@123')
        sid = edb("""INSERT INTO staff (employee_id,name,surname,email,password,phone,gender,date_of_joining,department,basic_salary,is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
            (emp_id,f.get('name'),f.get('surname',''),f.get('email'),hash_pw(pw_raw),
             f.get('phone',''),f.get('gender',''),date.today().isoformat(),f.get('department',0),f.get('basic_salary',0)))
        role_id = int(f.get('role_id',1))
        edb("INSERT OR REPLACE INTO staff_roles (staff_id,role_id) VALUES (?,?)", (sid,role_id))
        # If custom permissions selected
        if f.get('custom_permissions'):
            for mod in ALL_MODULES:
                v=1 if f.get(f'{mod}_view') else 0; a=1 if f.get(f'{mod}_add') else 0
                e=1 if f.get(f'{mod}_edit') else 0; d=1 if f.get(f'{mod}_delete') else 0
                edb("INSERT OR REPLACE INTO role_permissions (role_id,module,can_view,can_add,can_edit,can_delete) VALUES (?,?,?,?,?,?)",
                    (role_id,mod,v,a,e,d))
        audit('create','admin',sid,f'User {f.get("name")} created with role {role_id}')
        flash(f'User created! Emp ID: {emp_id} | Email: {f.get("email")} | Password: {pw_raw}','success')
        return redirect(url_for('admin_users'))
    roles = qdb("SELECT * FROM roles WHERE is_active=1 ORDER BY name")
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    role_perms = {}
    for r in roles:
        rows = qdb("SELECT * FROM role_permissions WHERE role_id=?", (r['id'],))
        role_perms[r['id']] = {rw['module']: {'view':bool(rw['can_view']),'add':bool(rw['can_add']),'edit':bool(rw['can_edit']),'delete':bool(rw['can_delete'])} for rw in rows}
    return render_template('admin/user_create.html', roles=roles, departments=departments, modules=ALL_MODULES, role_perms_json=json.dumps(role_perms), today=date.today().isoformat())

@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@perm_required('admin','edit')
def admin_user_toggle(uid):
    user = qdb("SELECT is_active FROM staff WHERE id=?", (uid,), one=True)
    if user:
        edb("UPDATE staff SET is_active=? WHERE id=?", (0 if user['is_active'] else 1, uid))
    flash('User status updated.','success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:uid>/reset_password', methods=['POST'])
@perm_required('admin','edit')
def admin_user_reset(uid):
    new_pw = request.form.get('new_password','admin@123')
    edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),uid))
    audit('reset_password','admin',uid,'Password reset by admin')
    flash(f'Password reset to: {new_pw}','success')
    return redirect(url_for('admin_users'))

@app.route('/admin/audit_log')
@perm_required('admin','view')
def admin_audit_log():
    page = int(request.args.get('page',1)); per_page = 50
    total = qdb("SELECT COUNT(*) as c FROM audit_log", one=True)['c']
    logs  = qdb("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (per_page,(page-1)*per_page))
    return render_template('admin/audit_log.html', logs=logs, page=page, per_page=per_page, total=total)

@app.route('/admin/settings', methods=['GET','POST'])
@perm_required('admin','edit')
def admin_settings():
    if request.method == 'POST':
        for key in ['name','email','phone','address','currency','currency_symbol','timezone','date_format','time_format','theme']:
            edb("INSERT OR REPLACE INTO sch_settings (name,value) VALUES (?,?)", (key, request.form.get(key,'')))
        # Update session currency symbol
        user = get_user()
        if user:
            user['currency_symbol'] = request.form.get('currency_symbol','$')
            user['school_name'] = request.form.get('name','Hospital')
            session['hospitaladmin'] = user
        flash('Settings saved.','success')
        return redirect(url_for('admin_settings'))
    settings = {r['name']:r['value'] for r in qdb("SELECT name,value FROM sch_settings")}
    return render_template('admin/settings.html', settings=settings)

@app.route('/admin/departments', methods=['GET','POST'])
@perm_required('admin','add')
def admin_departments():
    if request.method == 'POST':
        action = request.form.get('action','add')
        if action == 'add':
            edb("INSERT INTO department (department_name,description) VALUES (?,?)", (request.form.get('department_name'),request.form.get('description','')))
            flash('Department added.','success')
        elif action == 'delete':
            edb("UPDATE department SET is_active=0 WHERE id=?", (request.form.get('dept_id'),))
            flash('Department removed.','success')
    departments = qdb("SELECT * FROM department WHERE is_active=1 ORDER BY department_name")
    return render_template('admin/departments.html', departments=departments)

# ─────────────────────────────────────────────
# APP ENTRY
# ─────────────────────────────────────────────
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    else:
        # Run schema updates on existing db
        with app.app_context():
            db = get_db()
            db.executescript(SCHEMA)
            db.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)

# ─────────────────────────────────────────────
# JINJA FILTERS
# ─────────────────────────────────────────────
import json as _json
@app.template_filter('fromjson')
def fromjson_filter(s):
    try: return _json.loads(s)
    except: return {}

# ─────────────────────────────────────────────────────────────────────
# EMPLOYEE SELF-SERVICE PORTAL
# Every logged-in staff member can access their own data
# Routes are under /my/... — no special permission needed, just login
# ─────────────────────────────────────────────────────────────────────

@app.route('/my')
@login_required
def my_portal():
    """Employee self-service home dashboard"""
    user = get_user()
    sid  = user.get('id', 0)
    today = date.today().isoformat()
    month = date.today().strftime('%Y-%m')

    me = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,
        staff_designation.designation as designation_name
        FROM staff
        LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.id=?""", (sid,), one=True)
    if not me: return redirect(url_for('dashboard'))

    # My stats
    my_leaves_pending  = qdb("SELECT COUNT(*) as c FROM leave_applications WHERE staff_id=? AND status='pending'", (sid,), one=True)['c']
    my_leaves_approved = qdb("SELECT COUNT(*) as c FROM leave_applications WHERE staff_id=? AND status='approved'", (sid,), one=True)['c']
    my_attend_month    = qdb("SELECT COUNT(*) as c FROM attendance WHERE staff_id=? AND strftime('%Y-%m',date)=? AND status='present'", (sid,month), one=True)['c']
    my_absent_month    = qdb("SELECT COUNT(*) as c FROM attendance WHERE staff_id=? AND strftime('%Y-%m',date)=? AND status='absent'", (sid,month), one=True)['c']
    my_trainings       = qdb("SELECT COUNT(*) as c FROM training_participants WHERE staff_id=? AND status='enrolled'", (sid,), one=True)['c']
    last_payroll       = qdb("SELECT * FROM payroll WHERE staff_id=? ORDER BY year DESC, id DESC LIMIT 1", (sid,), one=True)

    # Today's attendance
    today_attend = qdb("SELECT * FROM attendance WHERE staff_id=? AND date=?", (sid,today), one=True)

    # Recent leave applications
    recent_leaves = qdb("""SELECT leave_applications.*,leave_types.name as leave_name
        FROM leave_applications
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        WHERE leave_applications.staff_id=? ORDER BY leave_applications.id DESC LIMIT 5""", (sid,))

    # Upcoming training
    upcoming_training = qdb("""SELECT training.*,training_participants.status as enroll_status
        FROM training JOIN training_participants ON training_participants.training_id=training.id
        WHERE training_participants.staff_id=? AND training_participants.status='enrolled'
        ORDER BY training.start_date DESC LIMIT 3""", (sid,))

    # Notice: pending appraisals
    appraisals = qdb("SELECT * FROM performance_appraisal WHERE staff_id=? ORDER BY id DESC LIMIT 3", (sid,))

    return render_template('my/portal.html',
        me=dict(me), my_leaves_pending=my_leaves_pending,
        my_leaves_approved=my_leaves_approved,
        my_attend_month=my_attend_month, my_absent_month=my_absent_month,
        my_trainings=my_trainings, last_payroll=dict(last_payroll) if last_payroll else {},
        today_attend=dict(today_attend) if today_attend else None,
        recent_leaves=recent_leaves, upcoming_training=upcoming_training,
        appraisals=appraisals, today=today, month=month)


@app.route('/my/leave', methods=['GET','POST'])
@login_required
def my_leave():
    """Employee applies for their own leave"""
    user = get_user()
    sid  = user.get('id', 0)
    if request.method == 'POST':
        f = request.form
        from_d = date.fromisoformat(f.get('from_date', date.today().isoformat()))
        to_d   = date.fromisoformat(f.get('to_date',   date.today().isoformat()))
        days   = (to_d - from_d).days + 1
        if days < 1:
            flash('To Date must be on or after From Date.', 'danger')
            return redirect(url_for('my_leave'))
        edb("""INSERT INTO leave_applications
               (staff_id,leave_type_id,from_date,to_date,total_days,reason)
               VALUES (?,?,?,?,?,?)""",
            (sid, f.get('leave_type_id'), f.get('from_date'), f.get('to_date'), days, f.get('reason','')))
        flash(f'Leave application submitted for {days} day(s). Waiting for HR approval.', 'success')
        return redirect(url_for('my_leave'))

    leave_types = qdb("SELECT * FROM leave_types WHERE is_active=1")
    my_leaves   = qdb("""SELECT leave_applications.*,leave_types.name as leave_name
        FROM leave_applications
        JOIN leave_types ON leave_types.id=leave_applications.leave_type_id
        WHERE leave_applications.staff_id=? ORDER BY leave_applications.id DESC""", (sid,))

    # Leave balance per type
    balances = {}
    for lt in leave_types:
        used = qdb("""SELECT COALESCE(SUM(total_days),0) as u FROM leave_applications
            WHERE staff_id=? AND leave_type_id=? AND status='approved'
            AND strftime('%Y',from_date)=?""",
            (sid, lt['id'], str(date.today().year)), one=True)['u']
        balances[lt['id']] = {'allowed': lt['days_allowed'], 'used': int(used),
                               'remaining': max(0, lt['days_allowed'] - int(used))}

    return render_template('my/leave.html',
        leave_types=leave_types, my_leaves=my_leaves,
        balances=balances, today=date.today().isoformat())


@app.route('/my/leave/<int:lid>/cancel', methods=['POST'])
@login_required
def my_leave_cancel(lid):
    """Employee cancels their own pending leave"""
    user = get_user()
    sid  = user.get('id', 0)
    # Only allow cancel if it belongs to this employee and is still pending
    leave = qdb("SELECT * FROM leave_applications WHERE id=? AND staff_id=? AND status='pending'", (lid,sid), one=True)
    if leave:
        edb("UPDATE leave_applications SET status='cancelled' WHERE id=?", (lid,))
        flash('Leave application cancelled.', 'success')
    else:
        flash('Cannot cancel — leave not found or already processed.', 'danger')
    return redirect(url_for('my_leave'))


@app.route('/my/attendance')
@login_required
def my_attendance():
    """Employee views their own attendance"""
    user  = get_user()
    sid   = user.get('id', 0)
    month = request.args.get('month', date.today().strftime('%Y-%m'))

    records = qdb("""SELECT * FROM attendance WHERE staff_id=? AND strftime('%Y-%m',date)=?
        ORDER BY date""", (sid, month))

    stats = {
        'present':  sum(1 for r in records if r['status']=='present'),
        'absent':   sum(1 for r in records if r['status']=='absent'),
        'late':     sum(1 for r in records if r['status']=='late'),
        'half_day': sum(1 for r in records if r['status']=='half_day'),
        'total':    len(records),
    }
    if stats['total'] > 0:
        stats['pct'] = round((stats['present'] + stats['half_day']*0.5) / stats['total'] * 100, 1)
    else:
        stats['pct'] = 0

    return render_template('my/attendance.html', records=records, stats=stats, month=month)


@app.route('/my/payslips')
@login_required
def my_payslips():
    """Employee views their own payslips"""
    user = get_user()
    sid  = user.get('id', 0)
    records = qdb("SELECT * FROM payroll WHERE staff_id=? ORDER BY year DESC, id DESC", (sid,))
    return render_template('my/payslips.html', records=records)


@app.route('/my/profile', methods=['GET','POST'])
@login_required
def my_profile():
    """Employee views and updates their own basic profile info"""
    user = get_user()
    sid  = user.get('id', 0)
    me = qdb("""SELECT staff.*,roles.name as role_name,department.department_name,
        staff_designation.designation as designation_name
        FROM staff
        LEFT JOIN staff_roles ON staff_roles.staff_id=staff.id
        LEFT JOIN roles ON roles.id=staff_roles.role_id
        LEFT JOIN department ON department.id=staff.department
        LEFT JOIN staff_designation ON staff_designation.id=staff.designation
        WHERE staff.id=?""", (sid,), one=True)
    if not me: return redirect(url_for('dashboard'))

    if request.method == 'POST':
        f = request.form
        # Only allow editing contact/personal fields — NOT role, salary, etc.
        edb("""UPDATE staff SET phone=?,mobileno=?,address=?,
               emergency_contact=?,blood_group=? WHERE id=?""",
            (f.get('phone'),f.get('mobileno'),f.get('address'),
             f.get('emergency_contact'),f.get('blood_group'),sid))
        # Password change
        current_pw = f.get('current_password','').strip()
        new_pw     = f.get('new_password','').strip()
        if current_pw and new_pw:
            if hash_pw(current_pw) == me['password']:
                edb("UPDATE staff SET password=? WHERE id=?", (hash_pw(new_pw),sid))
                flash('Password changed successfully.', 'success')
            else:
                flash('Current password is incorrect.', 'danger')
        else:
            flash('Profile updated successfully.', 'success')
        return redirect(url_for('my_profile'))

    return render_template('my/profile.html', me=dict(me))


@app.route('/my/training')
@login_required
def my_training():
    """Employee views their training records"""
    user = get_user()
    sid  = user.get('id', 0)
    records = qdb("""SELECT training.*,
        training_participants.status as enroll_status,
        training_participants.score,
        training_participants.certificate_issued,
        training_participants.completion_date
        FROM training
        JOIN training_participants ON training_participants.training_id=training.id
        WHERE training_participants.staff_id=? ORDER BY training.start_date DESC""", (sid,))
    return render_template('my/training.html', records=records)


@app.route('/my/appraisals')
@login_required
def my_appraisals():
    """Employee views their appraisal records"""
    user = get_user()
    sid  = user.get('id', 0)
    records = qdb("""SELECT performance_appraisal.*,
        staff.name||' '||staff.surname as reviewer_name
        FROM performance_appraisal
        LEFT JOIN staff ON staff.id=performance_appraisal.reviewer_id
        WHERE performance_appraisal.staff_id=? ORDER BY performance_appraisal.id DESC""", (sid,))
    return render_template('my/appraisals.html', records=records)

