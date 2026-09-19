# 🛡️ Honeypot Orchestrator

### AI-Assisted Cybersecurity Deception & Threat Analysis Platform

Honeypot Orchestrator is a cybersecurity research platform that uses decoy services to capture suspicious activity, classify attack behavior, track attack progression, and present the results through a centralized security dashboard.

The project combines **honeypots, machine learning, attack-chain analysis, threat scoring, and real-time visualization** into a single workflow.

<p align="center">



\

</p>

---

## 🎯 Problem

Security teams can receive large volumes of events from different services, making it difficult to identify meaningful attack behavior quickly.

Honeypot Orchestrator focuses on three practical challenges:

* Detecting suspicious activity across multiple service types.
* Converting raw security events into useful intelligence.
* Understanding how individual events develop into a larger attack sequence.

Instead of treating every event as an isolated alert, the platform maintains an **attacker-centric view** of activity.

---

## 💡 Solution

Honeypot Orchestrator creates controlled decoy environments that are designed to attract suspicious interactions.

When an interaction occurs, the platform:

```text
Deception
    ↓
Event Capture
    ↓
Feature Extraction
    ↓
ML Classification
    ↓
Severity Analysis
    ↓
Attack Chain Tracking
    ↓
Threat Intelligence
    ↓
SOC Dashboard
```

This provides a complete workflow from **detection to analysis and visualization**.

---

## 🌐 Live Demo

### 📊 Security Dashboard

https://honeypot-orchestrator.onrender.com/

### 🎮 Attack Control Panel

https://honeypot-orchestrator.onrender.com/attacker

The dashboard provides a centralized view of simulated security activity, while the attack control panel allows controlled attack scenarios to be generated for testing.

---

# 🚀 Key Features

## 🎭 Multi-Service Honeypots

The platform currently supports three types of decoy services:

* 🔐 **SSH Honeypot** — integrated with Cowrie
* 🌐 **HTTP Honeypot** — simulated endpoints and web interactions
* 🗄️ **Database Honeypot** — suspicious database activity detection

Additional decoy assets such as fake administrative panels, configuration files, and `.env` files can be used to increase the realism of the environment.

---

## 🧠 Machine Learning Classification

A **Random Forest classifier** is used to categorize security events.

### Model Configuration

| Parameter        |         Value |
| ---------------- | ------------: |
| Algorithm        | Random Forest |
| Number of Trees  |           200 |
| Maximum Depth    |             8 |
| Input Features   |            10 |
| Attack Classes   |             7 |
| Training Samples |         2,198 |
| Test Samples     |           550 |
| Test Accuracy    |    **94.18%** |

### Supported Attack Categories

* 🔑 Brute Force
* 💻 Command Injection
* 🔐 Credential Attack
* 💉 SQL Injection
* 🔎 Scanning
* 🌐 Suspicious HTTP
* ⚡ XSS

A rule-based fallback is also available when ML classification is unavailable.

---

# 📊 Model Performance

## Classification Results

| Attack Type          | Precision | Recall | F1-Score | Support |
| -------------------- | --------: | -----: | -------: | ------: |
| 🔑 Brute Force       |      1.00 |   1.00 |     1.00 |     224 |
| 💻 Command Injection |      1.00 |   1.00 |     1.00 |      10 |
| 🔐 Credential Attack |      1.00 |   1.00 |     1.00 |       6 |
| 💉 SQL Injection     |      1.00 |   1.00 |     1.00 |      15 |
| 🔎 Scanning          |      1.00 |   0.75 |     0.86 |     128 |
| 🌐 Suspicious HTTP   |      0.83 |   1.00 |     0.91 |     160 |
| ⚡ XSS                |      1.00 |   1.00 |     1.00 |       7 |
| **Overall**          |           |        | **0.94** | **550** |

### 🔍 Feature Importance

| Rank | Feature            | Importance |
| ---: | ------------------ | ---------: |
|    1 | `payload_length`   |      0.196 |
|    2 | `failed_attempts`  |      0.126 |
|    3 | `has_xss_pattern`  |      0.125 |
|    4 | `has_sqli_pattern` |      0.122 |
|    5 | `request_count`    |      0.115 |
|    6 | `is_http`          |      0.110 |
|    7 | `has_login`        |      0.069 |
|    8 | `is_ssh`           |      0.063 |
|    9 | `has_cmd_pattern`  |      0.060 |
|   10 | `is_db`            |      0.014 |

The current evaluation indicates that payload characteristics and failed authentication activity are among the strongest features for classification.

---

# ⛓️ Attack Chain Analysis

Instead of treating every event as an independent alert, the platform groups events by attacker and tracks their progression.

The current attack flow is represented as:

```text
RECON
  ↓
DISCOVERY
  ↓
CREDENTIAL ATTACK
  ↓
ACCESS ATTEMPT
  ↓
COMMAND EXECUTION
```

This provides a higher-level view of how an attack can progress from reconnaissance toward potential system access.

The system can also use the observed progression to identify the next likely stage within the simulated attack flow.

---

# 🚨 Threat Scoring

Each detected event receives a severity score on a **0–100 scale**.

| Severity    | Score Range |
| ----------- | ----------: |
| 🟢 LOW      |        0–25 |
| 🟡 MEDIUM   |       26–50 |
| 🟠 HIGH     |       51–75 |
| 🔴 CRITICAL |      76–100 |

The resulting severity is displayed on the dashboard and used as part of the threat-analysis workflow.

---

# 📊 SOC Dashboard

The web dashboard provides a centralized view of captured activity.

### Current capabilities

* 📡 Live attack event feed
* 🚨 Severity distribution
* 📈 Attack-type distribution
* 🕐 Time-based attack activity
* 👤 Top attacker tracking
* ⛓️ Attack-chain visualization
* 📄 Threat intelligence reports
* 📊 Attack statistics

The dashboard currently refreshes event information using a **3-second polling interval**.

---

# 🎮 Attack Control Panel

The project includes a dedicated interface for controlled attack simulation.

### Available modes

* Single attack
* Kill-chain simulation
* Attack storm
* Live console output
* Attack statistics

This allows the complete detection pipeline to be demonstrated without requiring a real external attacker.

---

# 🏗️ System Architecture

```text
                         ┌─────────────────────┐
                         │      ATTACKER       │
                         │     / SIMULATOR     │
                         └──────────┬──────────┘
                                    │
                  ┌─────────────────┼─────────────────┐
                  │                 │                 │
                  ▼                 ▼                 ▼
          ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
          │ SSH Honeypot │  │ HTTP Honeypot│  │ DB Honeypot  │
          │   Cowrie     │  │ Fake Service │  │ Fake DB      │
          └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                 │                 │                 │
                 └─────────────────┼─────────────────┘
                                   │
                                   ▼
                         ┌─────────────────────┐
                         │   Node.js Backend   │
                         │                     │
                         │ Event Processing    │
                         │ Feature Extraction  │
                         │ REST API            │
                         └──────────┬──────────┘
                                    │
                     ┌──────────────┼──────────────┐
                     │              │              │
                     ▼              ▼              ▼
              ┌────────────┐ ┌────────────┐ ┌────────────┐
              │ ML Model   │ │ Rule Engine│ │  SQLite DB │
              │ Random     │ │ Fallback   │ │  Storage   │
              │ Forest     │ │            │ │            │
              └─────┬──────┘ └─────┬──────┘ └────────────┘
                    │               │
                    └───────┬───────┘
                            ▼
                   ┌──────────────────┐
                   │  Threat Engine   │
                   │                  │
                   │ Severity Scoring │
                   │ Attack Chains    │
                   │ Threat Reports   │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │  SOC Dashboard   │
                   │                  │
                   │ React + Recharts │
                   └──────────────────┘
```

---

# 🛠️ Technology Stack

## 🎨 Frontend

* React 18
* Recharts
* HTML5
* CSS3
* Babel Standalone

## ⚙️ Backend

* Node.js 22+
* `node:http`
* `node:sqlite`
* REST API

## 🧠 Machine Learning

* Python 3.9+
* scikit-learn
* Pandas
* NumPy
* Joblib
* Flask

## 🔐 Security Components

* Cowrie
* HTTP decoy service
* Database decoy service
* Attack simulation engine

## ☁️ Deployment

* Render
* Git
* GitHub

---

# 📁 Project Structure

```text
honeypot-orchestrator/
│
├── backend/
│   ├── server.js
│   ├── db.js
│   ├── threatEngine.js
│   ├── reportGenerator.js
│   └── package.json
│
├── frontend/
│   ├── index.html
│   ├── attacker.html
│   ├── react.production.min.js
│   ├── react-dom.production.min.js
│   ├── Recharts.min.js
│   └── babel.min.js
│
├── ml/
│   ├── classifier.py
│   └── models/
│       └── attack_classifier.joblib
│
├── simulator/
│   └── simulate_attack.py
│
├── honeypots/
│   ├── http/
│   │   └── fake_server.py
│   ├── db/
│   │   └── fake_db.py
│   └── ssh/
│       └── README.md
│
├── database/
│   └── SQLite database
│
├── ml_server.py
├── requirements.txt
├── run_demo.sh
├── .gitignore
├── LICENSE
└── README.md
```

---

# 🚀 Quick Start

## 📋 Prerequisites

Make sure the following are installed:

* Node.js `22.5+`
* Python `3.9+`
* Git

## 1. Clone the Repository

```bash
git clone https://github.com/itchetanpreet-tech/honeypot-orchestrator.git
cd honeypot-orchestrator
```

## 2. Run the Demo

```bash
chmod +x run_demo.sh
./run_demo.sh
```

---

# ⚙️ Manual Setup

If you want to run each component individually, use three terminals.

### Terminal 1 — ML Server

```bash
python3 -m pip install -r requirements.txt
python3 ml_server.py
```

### Terminal 2 — Backend

```bash
cd backend
node --experimental-sqlite server.js
```

### Terminal 3 — Attack Simulator

```bash
cd simulator
python3 simulate_attack.py --attackers 8
```

### 🌐 Open the Dashboard

```text
Dashboard:
http://localhost:4000/

Attack Control Panel:
http://localhost:4000/attacker
```

---

# 🔄 How the System Works

### 1. 🎭 Deception

Decoy SSH, HTTP, and database services expose controlled targets designed to receive suspicious interactions.

### 2. 📥 Event Capture

Interactions are converted into security events and sent to the backend through:

```text
POST /api/events
```

### 3. 🔍 Feature Extraction

The backend extracts ten engineered features from each event.

### 4. 🧠 Classification

The Random Forest model classifies the event into one of the supported attack categories.

If the ML service is unavailable, the rule-based detection layer can provide fallback classification.

### 5. ⚖️ Severity Analysis

The event receives a severity score between 0 and 100.

### 6. ⛓️ Attack Chain Tracking

Events are grouped by attacker and used to construct an attack progression.

### 7. 📊 Visualization

The dashboard presents:

* Current events
* Severity levels
* Attack distribution
* Attacker activity
* Attack chains
* Threat reports

---

# 📈 Demonstrated Results

The current demonstration environment has produced the following results:

| Metric                    |        Result |
| ------------------------- | ------------: |
| Security Events           |    **2,340+** |
| Tracked Attackers         |         **8** |
| Critical Threats          |        **35** |
| ML Test Accuracy          |    **94.18%** |
| Attack Categories         |         **7** |
| Dashboard Update Interval | **3 seconds** |

> These values represent the project's current demonstration environment rather than production-scale security telemetry.

---

# 🔐 Security Considerations

Honeypot Orchestrator is designed as an **educational and research-oriented security project**.

Important considerations:

* Honeypots should be isolated from production systems.
* No real credentials should be placed inside decoy services.
* Synthetic attack traffic should be used for demonstrations.
* Input validation is applied before processing events.
* Backend event handling includes rate limiting.
* Database operations use parameterized queries.
* The system should not be treated as a replacement for a production SOC or security appliance.

> ⚠️ **Important:** Deploy honeypots only in controlled and isolated environments.

---

# 🎯 Use Cases

### 🛡️ Security Operations

Provide a consolidated view of suspicious activity and attack progression.

### 🔬 Cybersecurity Research

Study attack patterns and behavioral characteristics in a controlled environment.

### 🎓 Security Education

Demonstrate how attacks can be captured, classified, scored, and visualized.

### 🔎 Threat Analysis

Organize individual security events into attacker-centric activity chains.

### 🧪 Red-Team Simulation

Generate controlled attack scenarios for testing the detection pipeline.

---

# 🔮 Future Development

## Short Term

* Additional honeypot services such as SMTP, FTP, RDP, and Telnet
* Real-time notification channels
* Mobile monitoring interface

## Medium Term

* Deep learning-based classification
* Automated threat hunting
* MITRE ATT&CK mapping

## Long Term

* Multi-cloud deployment
* Distributed honeypot infrastructure
* STIX/TAXII-based threat intelligence sharing

---

# 🏆 Hackathon Context

**Morrow 1.0 — Makers Need More (MnM)**

**Track:** AI/ML-based Cybersecurity Solution

The project addresses the track through a combination of:

* 🎭 Multi-service deception
* 🧠 Machine learning-based attack classification
* ⚙️ Automated event analysis
* ⛓️ Attack-chain tracking
* 📊 Security visualization
* 🌐 A working cloud-deployed prototype

The current prototype is available online for demonstration.

---

# ⭐ Project Highlights

| Capability             | Implementation                                        |
| ---------------------- | ----------------------------------------------------- |
| 🛡️ Deception          | SSH, HTTP & Database Honeypots                        |
| 🧠 Classification      | Random Forest                                         |
| 📊 Test Accuracy       | 94.18%                                                |
| 🎯 Attack Categories   | 7                                                     |
| ⛓️ Attack Analysis     | Kill-chain progression                                |
| 🚨 Threat Scoring      | 0–100 severity scale                                  |
| 📡 Monitoring          | Real-time dashboard                                   |
| 🎮 Simulation          | Attack control panel                                  |
| 📄 Intelligence        | Automated threat reports                              |
| ☁️ Deployment          | Render                                                |
| 💰 Infrastructure Cost | No paid infrastructure required for current prototype |

---

# 🌐 Live Links

### 📊 Dashboard

https://honeypot-orchestrator.onrender.com/

### 🎮 Attack Simulator

https://honeypot-orchestrator.onrender.com/attacker

### 💻 GitHub Repository

https://github.com/itchetanpreet-tech/honeypot-orchestrator

---

# 👨‍💻 Author

### Chetanpreet Singh

**B.Tech CSE — Chandigarh University**

📧 [24bcs10951@cuchd.in](mailto:24bcs10951@cuchd.in)
🐙 https://github.com/itchetanpreet-tech

---

# 🙏 Acknowledgements

* 🏆 Morrow 1.0 — Makers Need More (MnM)
* 🎓 Chandigarh University
* 🐚 Cowrie Project
* 🧠 scikit-learn
* 🌍 Open-source cybersecurity community

---

# 📄 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

## ⚠️ Project Disclaimer

Honeypot Orchestrator is intended for **educational, research, and controlled security-testing purposes**.

Do not deploy decoy infrastructure on networks where it could expose real systems, credentials, or sensitive information.

---

<p align="center">

### 🛡️ Honeypot Orchestrator

**Deception → Detection → Classification → Analysis → Intelligence**

</p>
