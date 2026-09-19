# 🛡️ Honeypot Orchestrator — AI Security Command Center

An AI-powered cybersecurity deception platform that uses fake decoy services (SSH, HTTP, Database) to attract and detect attackers. Uses a Random Forest ML model (94.18% accuracy) to classify 7 attack types in real-time.

[![Live Demo](https://img.shields.io/badge/Demo-Live-success)](https://honeypot-orchestrator.onrender.com/)
[![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-94.18%25-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-blue)]()
[![Node](https://img.shields.io/badge/Node.js-22.5%2B-green)]()

---

## 🌐 Live Demo

| Page | URL |
|------|-----|
| **Dashboard** | [https://honeypot-orchestrator.onrender.com/](https://honeypot-orchestrator.onrender.com/) |
| **Attack Control Panel** | [https://honeypot-orchestrator.onrender.com/attacker](https://honeypot-orchestrator.onrender.com/attacker) |

---

## 🎯 Key Features

- 🎭 **3 Honeypots**: SSH, HTTP, Database decoys
- 🧠 **ML Classification**: 94.18% accuracy, 7 attack types
- ⛓️ **Attack Chains**: RECON → DISCOVERY → CREDENTIAL ATTACK → ACCESS ATTEMPT → COMMAND EXECUTION
- 📊 **Real-time Dashboard**: Live monitoring (3s polling)
- 📄 **Threat Intelligence Reports**: AI-generated
- 🎮 **Attack Control Panel**: Trigger attacks from UI
- 💰 **Zero Investment**: Built with 100% free tools

---

## 🧠 ML Model Performance

| Metric | Value |
|--------|-------|
| **Accuracy** | **94.18%** |
| **Model** | Random Forest Classifier |
| **Trees** | 200 |
| **Max Depth** | 8 |
| **Features** | 10 |
| **Classes** | 7 attack types |

### Classification Report

| Attack Type | Precision | Recall | F1-Score | Support |
|-------------|-----------|--------|----------|---------|
| Brute Force | 1.00 | 1.00 | 1.00 | 224 |
| Command Injection | 1.00 | 1.00 | 1.00 | 10 |
| Credential Attack | 1.00 | 1.00 | 1.00 | 6 |
| SQL Injection | 1.00 | 1.00 | 1.00 | 15 |
| Scanning | 1.00 | 0.75 | 0.86 | 128 |
| Suspicious HTTP | 0.83 | 1.00 | 0.91 | 160 |
| XSS | 1.00 | 1.00 | 1.00 | 7 |

### Feature Importance

| Feature | Importance |
|---------|------------|
| payload_length | 0.196 |
| failed_attempts | 0.126 |
| has_xss_pattern | 0.125 |
| has_sqli_pattern | 0.122 |
| request_count | 0.115 |
| is_http | 0.110 |
| has_login | 0.069 |
| is_ssh | 0.063 |
| has_cmd_pattern | 0.060 |
| is_db | 0.014 |

---

## 🏗️ Architecture
Attacker/Simulator
│
▼
┌─────────────────┐
│ HONEYPOTS │ SSH | HTTP | Database
└────────┬─────────┘
│ POST /api/events
▼
EVENT PROCESSOR (Node.js)
│
├─► SQLite Database
│
▼
THREAT ENGINE
— ML Classification (Random Forest - 94.18%)
— Rule-based Fallback
│
├─► AI Threat Reports
└─► Attack Chain Analysis
│
▼
SOC DASHBOARD (React)
— Real-time polling (3 seconds)
— Live attack feed
— Attack chain visualization
— Severity breakdown
## 🚀 Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React.js, Recharts, HTML5, CSS3 |
| **Backend** | Node.js (built-in http + sqlite modules) |
| **ML/AI** | Python, scikit-learn, Pandas, NumPy, Joblib |
| **Database** | SQLite |
| **Deployment** | Render (Free Tier) |
| **Version Control** | Git, GitHub |

---

## 🛠️ Local Setup

### Prerequisites

- **Node.js** >= 22.5.0
- **Python** >= 3.9

### Installation Steps

# 1. Clone the repository
git clone https://github.com/itchetanpreet-tech/honeypot-orchestrator.git
cd honeypot-orchestrator

# 2. Install Python dependencies
python3 -m pip install -r requirements.txt

# 3. Train the ML model
cd ml
python3 classifier.py
cd ..

# 4. Start ML Server (Terminal 1)
python3 ml_server.py

# 5. Start Backend (Terminal 2)
cd backend
node --experimental-sqlite server.js

# 6. Generate attack traffic (Terminal 3)
cd simulator
python3 simulate_attack.py --attackers 8

# 7. Open in browser
# Dashboard:      http://localhost:4000/
# Attacker Panel: http://localhost:4000/attacker

📂 Project Structure
honeypot-orchestrator/
├── backend/                 # Node.js API server
│   ├── server.js           # Main server with ML integration
│   ├── db.js               # SQLite database layer
│   ├── threatEngine.js     # Rule-based classifier
│   ├── reportGenerator.js  # AI threat reports
│   └── package.json
├── frontend/                # React dashboard
│   ├── index.html          # SOC dashboard
│   └── attacker.html       # Attack control panel
├── ml/                      # ML pipeline
│   ├── classifier.py       # Random Forest training
│   └── models/
│       └── attack_classifier.joblib
├── simulator/               # Attack simulator
│   └── simulate_attack.py
├── honeypots/               # Decoy services
│   ├── http/fake_server.py
│   ├── db/fake_db.py
│   └── ssh/README.md       # Cowrie setup guide
├── database/                # SQLite (auto-generated)
├── ml_server.py             # ML microservice (Flask)
├── requirements.txt         # Python dependencies
├── LICENSE
└── README.md

🎬 How It Works
Honeypots attract attackers with fake services (SSH, HTTP, DB)

Backend receives events via REST API

ML Model classifies attacks with 94.18% accuracy

Dashboard displays real-time attack data (3s polling)

Attack Chains show attacker progression

Threat Reports generate actionable intelligence

🏆 Achievements
✅ 94.18% ML Accuracy

✅ Zero Investment (100% free tools)

✅ Live Deployment on Render

✅ Real-time Classification

✅ 7 Attack Types Detected

✅ Attack Chain Prediction

🔮 Future Scope
🔐 More honeypots (SMTP, FTP, RDP, Telnet)

🧠 Deep Learning models (LSTM/GRU)

📱 Mobile app for monitoring

☁️ Full AWS/Azure deployment

🚨 Real-time alerts (Email/SMS/Slack)

📊 Advanced analytics dashboard

👥 Author
Chetanpreet Singh
B.Tech CSE | Chandigarh University
📧 24bcs10951@cuchd.in
🐙 GitHub

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Morrow 1.0 Hackathon by Makers Need More (MnM)

Chandigarh University for support

Open-source community for amazing tools and libraries

Cowrie project for SSH honeypot inspiration

⭐ Star This Repository
If you found this project helpful, please consider giving it a ⭐!