# 🛡️ Pairadox BGP Sentinel
### Explainable BGP Origin and Subprefix Anomaly Monitor

**AIORI Hackathon 3.0 | Cybersecurity Track | Problem Statement PS-005**


[![Live Demo](https://img.shields.io/badge/Live_Demo-Vercel-000000?style=for-the-badge&logo=vercel)](https://snehali-dey-pairadox-bgp-sentinel.vercel.app/)
[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com/docs)
[![Frontend](https://img.shields.io/badge/Frontend-React-61DAFB?style=for-the-badge&logo=react)](https://snehali-dey-pairadox-bgp-sentinel.vercel.app/)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python)

---

## 🌐 Live Application

**Dashboard:** https://snehali-dey-pairadox-bgp-sentinel.vercel.app/

**Backend API:** https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com/

**Interactive API Documentation:** https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com/docs

**Source Code:** https://github.com/CipherGriffin07/snehali-dey-pairadox-bgp-sentinel

The application is publicly accessible through the live dashboard link.


## 📌 Problem Statement

The Border Gateway Protocol (BGP) is responsible for exchanging routing information between Autonomous Systems (ASes) across the Internet.

However, BGP does not inherently guarantee that an Autonomous System is authorized to announce a particular IP prefix.

This creates opportunities for routing incidents such as:

- **BGP Origin Hijacking:** An unexpected Autonomous System announces a prefix previously associated with another origin.
- **Subprefix Hijacking:** A more-specific IP prefix is announced, potentially attracting traffic because routers generally prefer more-specific routes.
- **Unauthorized Route Announcements:** Announcements conflict with available route-origin authorization information.

Such incidents can lead to traffic redirection, interception, service disruption, and loss of connectivity.

### Our Objective

Develop an explainable monitoring system that can identify suspicious BGP origin and subprefix announcements, provide supporting evidence, and help security analysts understand why an event deserves investigation.

---

## 💡 Our Solution

**Pairadox BGP Sentinel** is a web-based BGP anomaly detection and visualization platform.

It allows users to submit BGP announcements, analyze them against previously observed routes and demo RPKI authorization records, and inspect security alerts through an interactive dashboard.

Instead of presenting only a warning, the system aims to explain the reason behind each detected anomaly.

The prototype focuses on three core capabilities:

1. **Origin Change Detection** — Identifies changes in the origin ASN associated with an observed network prefix.
2. **Subprefix Anomaly Detection** — Identifies suspicious more-specific prefix announcements in relation to existing routes.
3. **Demo RPKI Validation** — Checks announcements against a local set of Route Origin Authorization (ROA) records.

---

## ✨ Key Features

### 🔍 Explainable Anomaly Detection

- Detects origin ASN changes.
- Detects subprefix-related anomalies.
- Generates alerts for suspicious routing behavior.
- Provides explanations to support investigation.

### 🛡️ RPKI-Inspired Validation

- Checks announced prefixes and ASNs against demo ROA records.
- Classifies authorization results as `VALID`, `INVALID`, or `NOT_FOUND`.
- Highlights announcements that conflict with the configured demo authorization data.

### 📊 Security Operations Dashboard

- Observed prefix statistics.
- Total anomaly alerts.
- Critical alert counts.
- RPKI-invalid event counts.
- Interactive routing and security visualizations.

### 🌐 Routing Topology Visualization

- Illustrates relationships derived from submitted routing information.
- Helps users explore observed routing behavior.
- Provides a simulated visual representation for demonstration purposes.

### 🚨 Threat Intelligence and Activity

- Displays detected security events.
- Supports investigation of suspicious announcements.
- Organizes routing alerts for easier analysis.

### 🧪 Interactive Test Scenarios

- Valid origin announcement.
- Origin change.
- Subprefix anomaly.

### 💾 Data Storage

- Uses SQLite for local persistence.
- Stores routing and alert information for the prototype.
- Supports resetting the demonstration data.

### 📁 Export Capability

- Supports CSV export for dashboard data.

---

## 🏗️ System Architecture

```text
                   USER / SECURITY ANALYST
                             |
                             v
                  REACT + VITE FRONTEND
                   (Hosted on Vercel)
                             |
                         HTTP / JSON
                             |
                             v
                     FASTAPI BACKEND
                     (Hosted on Render)
                             |
             +---------------+---------------+
             |               |               |
             v               v               v
       BGP DETECTOR     RISK SCORING     DEMO RPKI
             |               |          VALIDATION
             +---------------+---------------+
                             |
                             v
                       SQLITE STORAGE
                             |
                             v
                   ALERTS / ROUTES / STATS
                             |
                             v
                    DASHBOARD VISUALIZATION
```

### Processing Workflow

1. The user submits an IP prefix and origin ASN.
2. FastAPI validates the submitted information.
3. The detection engine compares the announcement with observed routing data.
4. The system evaluates origin changes and subprefix relationships.
5. Demo RPKI validation checks the announcement against configured ROA records.
6. The risk-scoring component evaluates detected anomalies.
7. Results are stored and exposed through API endpoints.
8. The dashboard displays updated statistics, explanations, and alerts.

---

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript |
| Styling | CSS |
| Backend | Python, FastAPI |
| API Server | Uvicorn |
| Data Validation | Pydantic |
| Database | SQLite |
| Testing | Pytest |
| Frontend Hosting | Vercel |
| Backend Hosting | Render |
| Version Control | Git, GitHub |

---

## 🧠 Detection Methodology

### 1. Origin Change Detection

The system compares the origin ASN of a newly submitted announcement with the origin ASN previously observed for the same network prefix.

**Example:**

Initial announcement:

```text
Prefix: 203.0.113.0/24
Origin ASN: 64500
```

New announcement:

```text
Prefix: 203.0.113.0/24
Origin ASN: 64599
```

The prefix remains the same, but the origin ASN changes.

**Interpretation:** The change may indicate a legitimate routing update, a configuration issue, or a potential origin hijacking attempt. Further investigation is required.

### 2. Subprefix Anomaly Detection

A subprefix is a more-specific network contained within a larger IP prefix.

**Example:**

Previously observed route:

```text
203.0.113.0/24
Origin ASN: 64500
```

New announcement:

```text
203.0.113.0/25
Origin ASN: 64599
```

The `/25` prefix is more specific than the `/24` prefix.

**Interpretation:** An unexpected more-specific announcement can be suspicious because Internet routing generally prefers the longest matching prefix.

### 3. Demo RPKI Validation

Resource Public Key Infrastructure (RPKI) helps validate whether an Autonomous System is authorized to originate an IP prefix.

The prototype implements a local demonstration of Route Origin Authorization checks.

| Status | Meaning |
|---|---|
| VALID | ASN and prefix length satisfy a matching demo ROA |
| INVALID | Announcement conflicts with the configured demo ROA records |
| NOT_FOUND | No applicable demo ROA record is available |

**Important:** This prototype uses local sample authorization records rather than a production RPKI validator or live global ROA dataset.

---

## 🧪 Example Test Cases

### Test 1 — Valid Origin

```text
Network Prefix: 203.0.113.0/24
Origin ASN: 64500
```

**Expected:** The route is accepted without an origin-change or RPKI-invalid alert.

### Test 2 — Origin Change

Run after Test 1:

```text
Network Prefix: 203.0.113.0/24
Origin ASN: 64599
```

**Expected:** The system identifies the changed origin ASN and generates an anomaly alert.

### Test 3 — Subprefix Announcement

Run after establishing the parent route:

```text
Network Prefix: 203.0.113.0/25
Origin ASN: 64599
```

**Expected:** The system identifies the more-specific announcement and evaluates it for subprefix-related anomalies.

These examples use documentation IP ranges and private-use ASNs for demonstration.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Project information |
| GET | `/health` | API health check |
| POST | `/analyze` | Analyze a BGP announcement |
| GET | `/alerts` | Retrieve detected alerts |
| GET | `/routes` | Retrieve observed routes |
| GET | `/stats` | Retrieve dashboard statistics |
| POST | `/reset` | Reset demonstration data |
| GET | `/docs` | Interactive API documentation |

### Sample API Request

```bash
curl -X POST \
  https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"prefix":"203.0.113.0/24","origin_asn":64500}'
```

---

## 💻 Local Installation and Setup

### Prerequisites

- Python 3
- Node.js and npm
- Git

### Step 1 — Clone the Repository

```bash
git clone https://github.com/CipherGriffin07/snehali-dey-pairadox-bgp-sentinel.git
cd snehali-dey-pairadox-bgp-sentinel
```

### Step 2 — Start the Backend

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

uvicorn main:app --reload
```

For Windows, activate the virtual environment using:

```powershell
.venv\Scripts\Activate.ps1
```

Backend:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### Step 3 — Start the Frontend

Open another terminal from the project root:

```bash
cd frontend

npm install

npm run dev
```

Frontend:

```text
http://localhost:5173
```

The frontend uses the local API by default. To point it to another backend, configure the `VITE_API_URL` environment variable.

---

## 🧪 Running Backend Tests

From the `backend` directory:

```bash
python -m pytest -v
```

The repository includes automated tests for the anomaly detection implementation.

---

## 📂 Project Structure

```text
Pairadox-BGP-Sentinel/
│
├── backend/
│   ├── main.py
│   ├── detector.py
│   ├── risk.py
│   ├── rpki.py
│   ├── storage.py
│   ├── models.py
│   ├── test_detection.py
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── cyber-enhancements.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── .gitignore
└── README.md
```

---

## 🚀 Deployment

The application uses separate frontend and backend deployments.

### Frontend — Vercel

- Framework: Vite
- Root directory: `frontend`
- Production URL: https://snehali-dey-pairadox-bgp-sentinel.vercel.app/

### Backend — Render

- Runtime: Python 3
- Root directory: `backend`
- Build command: `pip install -r requirements.txt`
- Start command:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

- Production URL: https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com/

The frontend connects to the backend using:

```text
VITE_API_URL=https://snehali-dey-pairadox-bgp-sentinel-api.onrender.com
```

The FastAPI CORS configuration permits requests from the deployed Vercel frontend.

**Hosting note:** The free Render instance may become inactive after periods of inactivity, causing a delay on the next request. SQLite data on this instance is not guaranteed to survive redeployment or restart.

---

## ⚠️ Current Limitations

Pairadox BGP Sentinel is a hackathon demonstration prototype, not a production Internet routing security platform.

Current limitations include:

- BGP announcements are submitted through the demonstration interface rather than collected from live global routing feeds.
- RPKI validation uses a local demo ROA dataset.
- Detection is based on observed announcements and heuristic rules; an alert does not prove malicious activity.
- The routing topology is illustrative rather than a complete representation of Internet connectivity.
- SQLite storage on the free deployment is ephemeral.
- The prototype is not intended for automated production routing decisions.

---

## 🔮 Future Enhancements

- Integrate real-time BGP data from public routing collectors.
- Connect to production RPKI validation sources.
- Incorporate historical routing context and trusted origin information.
- Add alert deduplication and configurable detection thresholds.
- Implement persistent cloud database storage.
- Add analyst authentication and role-based access control.
- Introduce incident investigation workflows and notification integrations.
- Expand support for large-scale route monitoring and historical analysis.

---

## 🎯 Project Impact

Pairadox BGP Sentinel demonstrates how explainable detection can help security analysts identify and understand suspicious Internet routing announcements.

By combining origin-change detection, subprefix analysis, demo RPKI validation, risk scoring, and a visual dashboard, the project provides an accessible environment for studying BGP routing security.

The long-term vision is to make BGP anomaly monitoring more understandable, transparent, and actionable.

---

**Developed by Team Pairadox for AIORI Hackathon 3.0.**

*Detect suspicious routes. Understand the evidence. Investigate with confidence.*
