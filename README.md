# 🏥 Hospital Management System v3.0

**Python Flask + SQLite | Complete End-to-End Hospital Software**

---

## 🚀 Quick Start (1 command)

```bash
pip install flask
python app.py
# Open: http://localhost:5000
```

---

## 🔑 Default Login Credentials

| Role | Email | Password | Access |
|------|-------|----------|--------|
| **Super Admin** | admin@hospital.com | admin123 | Everything |
| **Doctor** | doctor@hospital.com | admin123 | Patients, OPD, IPD, Lab |
| **Nurse** | nurse@hospital.com | admin123 | Patients, OPD, IPD, Beds |
| **Pharmacist** | pharmacist@hospital.com | admin123 | Pharmacy only |
| **Receptionist** | reception@hospital.com | admin123 | Patients, Appointments |
| **Accountant** | accounts@hospital.com | admin123 | Finance, Payroll |
| **HR Manager** | hr@hospital.com | admin123 | HR modules |

---

## 💊 Pharmacy Module (Full End-to-End)

| Feature | Route |
|---------|-------|
| Medicine Stock | `/pharmacy` |
| Add New Medicine | `/pharmacy/add` |
| Edit Medicine | `/pharmacy/<id>/edit` |
| **Add Stock / Purchase-In** | `/pharmacy/<id>/stock-in` |
| **Dispense to Patient** | `/pharmacy/dispense` |
| **Dispense Log (by date)** | `/pharmacy/dispense/all` |
| **Patient Medicine History** | `/pharmacy/dispense/patient/<id>` |
| Purchase Log | `/pharmacy/purchases` |

### Dispense Workflow
1. Go to **Dispense Medicines** page
2. Select patient by name or ID
3. Add multiple medicine rows (auto-loads batches, prices, stock)
4. System shows live bill summary
5. On save: stock is auto-deducted, dispense record created

---

## 👥 User Management

### Creating Users (Admin Panel)
1. Go to **Admin → User Management → Create New User**
2. Fill name, email, password
3. Assign role (Doctor, Nurse, Pharmacist, etc.)
4. User gets immediate login access with their credentials
5. Their sidebar shows ONLY the modules their role permits

### Role-Based Access Control (21 Modules)
- **21 modules** each with: View / Add / Edit / Delete permissions
- **9 default roles** pre-configured
- Create **custom roles** with any permission combination
- Permissions auto-apply to sidebar navigation

### Changing a User's Password
- **Admin Panel → User Management** → "Reset PW" button
- OR **Staff → Edit Staff → New Password** field
- OR user's own profile via Staff view

---

## 📦 All Modules

### 🏥 Clinical
- **Appointments** — Book with doctor/dept/priority (Normal/High/Urgent), status tracking
- **Patients** — Full demographics, auto-ID (PID0001), blood group, profile history
- **OPD** — Visit records, doctor, payment, TPA/insurance linkage, follow-up
- **IPD** — Admissions, bed assignment, discharge workflow
- **Bed Management** — Real-time occupancy map, types, wards, charges
- **Laboratory** — Test orders, results entry, normal ranges, pending tracking

### 💊 Pharmacy (Complete)
- **Medicine Stock** — Inventory with low-stock alerts (red/yellow/green), expiry warnings
- **Add Medicine** — With opening batch, price, stock
- **Stock-In / Purchase** — Add batches from suppliers, auto-update inventory
- **Dispense to Patient** — Multi-medicine per visit, auto bill, stock deduction
- **Dispense Log** — Date-wise log of all medicines given
- **Purchase Log** — All stock additions with supplier info

### 🏛 Operations
- **Blood Bank** — 8 blood groups, donations, inventory, requests + approval
- **Insurance/TPA** — Organization management, coverage limits, OPD/IPD linkage
- **Ambulance/Vehicle** — Fleet, trip logs, distance, charges
- **Visitors** — Registration, patient linkage

### 👨‍💼 Human Resources
- **Staff** — Complete profiles, employee IDs, login creation, bank details
- **Payroll** — Monthly salary, allowances, deductions, payment tracking
- **Leave Management** — 5 leave types, applications, approve/reject workflow
- **Attendance** — Daily bulk marking, time in/out, monthly % report
- **Performance Appraisal** — 5-criteria scoring, auto-grades (A+/A/B/C/D)
- **Training & Certification** — Programs, enrollment, completion, certificates

### 💰 Finance
- **Income** — Category-based recording, date filtering, totals
- **Expenses** — Category-based, date filtering
- **Reports** — Financial P&L, Patient stats, HR summary, Pharmacy revenue

### 🔐 Administration
- **Admin Panel** — Overview with stats, login history, recent audit trail
- **User Management** — All users, activate/deactivate, reset passwords
- **Create New User** — Name, email, password, role assignment with live permission preview
- **Roles & Permissions** — Matrix: toggle View/Add/Edit/Delete per module
- **Audit Log** — Every action timestamped with user, IP, module, details
- **Settings** — Hospital name, currency, timezone, theme
- **Departments** — Add/remove departments

---

## 🛠 Tech Stack

- **Language**: Python 3.x
- **Framework**: Flask
- **Database**: SQLite (auto-created as `hms.db`)
- **Templates**: Jinja2 with modern CSS (no external CSS framework needed)
- **Charts**: Chart.js (CDN)
- **Dependencies**: Only `flask`

---

## 📁 Project Structure

```
hms_v3/
├── app.py              ← Complete application (1900+ lines)
├── hms.db              ← Auto-created database
├── README.md           ← This file
├── uploads/            ← File uploads directory
└── templates/          ← 60+ HTML templates
    ├── base.html       ← Master layout with sidebar
    ├── login.html      ← Standalone login page
    ├── dashboard.html  ← Home with stats + charts
    ├── pharmacy/       ← list, add, edit, stock_in, dispense, dispense_all, purchases
    ├── patients/       ← list, add, view, edit
    ├── appointments/   ← list, add
    ├── opd/, ipd/, beds/, lab/
    ├── staff/          ← list, add, view, edit
    ├── payroll/        ← list, add
    ├── hr/             ← leave, attendance, appraisal, training (all sub-modules)
    ├── bloodbank/      ← index, donate, request
    ├── insurance/      ← list, add
    ├── vehicle/        ← list, add, trip
    ├── visitors/       ← list, add
    ├── income/         ← list, add
    ├── expenses/       ← list, add
    ├── reports/        ← index, financial, patients, hr, pharmacy
    └── admin/          ← panel, users, user_create, roles, role_permissions, audit_log, settings, departments
```
