# NetSentinel
<div align="center">

<img src="https://user-gen-media-assets.s3.amazonaws.com/gpt4o_images/22fc0602-2220-41f9-ac4e-1736934532a0.png" alt="NetSentinel logo" width="180">

# 🛡️ NetSentinel

### Lightweight SIEM — Real-Time Network Threat Detection & Dashboard







> A lightweight, modular Security Information and Event Management (SIEM) system built as a university dissertation project. NetSentinel combines Python-based monitoring agents with a real-time PHP web dashboard and MongoDB storage to detect, log, and visualise network threats.

</div>

***

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

***

## Overview

NetSentinel is a university dissertation project that implements a lightweight SIEM (Security Information and Event Management) solution designed for resource-constrained environments. Unlike enterprise SIEM platforms, NetSentinel focuses on simplicity, extensibility, and real-time visibility — making it suitable for small networks, research labs, and educational settings.

The system operates through distributed Python agents that monitor hosts and network traffic, forwarding structured event data to a central MongoDB database. A PHP-powered web dashboard provides analysts with live event feeds, alert management, and basic threat visualisations.

***

## Features

- 🔍 **Real-Time Event Monitoring** — Lightweight agents continuously capture system and network events
- 🚨 **Alerting Engine** — Rule-based alert generation for common threat signatures (port scans, brute force, suspicious processes)
- 📊 **Interactive Dashboard** — PHP/HTML5 frontend for live event stream, alert triaging, and statistics
- 🗄️ **MongoDB Storage** — Flexible schema for heterogeneous log ingestion and fast querying
- 🤖 **Modular Agent Design** — Plug-in architecture allows new detection modules to be added without modifying core code
- 🌐 **Multi-Host Support** — Agents can be deployed across multiple hosts, all reporting to a central collector
- 📈 **Visualisations** — Charts and graphs for event trends, top talkers, and alert severity distribution
- 🔐 **Severity Classification** — Events tagged LOW / MEDIUM / HIGH / CRITICAL with colour-coded dashboard indicators

***

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetSentinel                              │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │  Agent Host 1│   │  Agent Host 2│   │  Agent Host N... │   │
│  │  (Python)    │   │  (Python)    │   │  (Python)        │   │
│  └──────┬───────┘   └──────┬───────┘   └────────┬─────────┘   │
│         │                  │                     │             │
│         └──────────────────┼─────────────────────┘             │
│                            │ JSON Events (HTTP/TCP)             │
│                     ┌──────▼──────┐                            │
│                     │  Collector  │                            │
│                     │  (Python)   │                            │
│                     └──────┬──────┘                            │
│                            │                                   │
│                     ┌──────▼──────┐                            │
│                     │   MongoDB   │                            │
│                     │  (events /  │                            │
│                     │   alerts)   │                            │
│                     └──────┬──────┘                            │
│                            │                                   │
│                     ┌──────▼──────┐                            │
│                     │  Dashboard  │                            │
│                     │  (PHP/HTML) │                            │
│                     └─────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

***

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Monitoring Agents | Python 3.10+ | Host & network event collection |
| Collector | Python (Flask / raw socket) | Centralised event ingestion |
| Database | MongoDB 6.x | Event & alert storage |
| Dashboard Backend | PHP 8.x | REST API & server-side rendering |
| Dashboard Frontend | HTML5 / CSS3 / JavaScript | Real-time UI |
| Charting | Chart.js | Dashboard visualisations |
| Agent Modules | Python (psutil, scapy, etc.) | Pluggable detection modules |

***

## Getting Started

### Prerequisites

- Python 3.10+
- PHP 8.x with MongoDB extension (`mongodb` PECL extension)
- MongoDB 6.x (local or Atlas)
- Composer (PHP dependency manager)
- pip & virtualenv

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/<your-username>/netsentinel.git
cd netsentinel
```

2. **Set up the Python environment**

```bash
cd agent
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Configure MongoDB**

```bash
# Start MongoDB locally (or update config with your Atlas URI)
mongod --dbpath /data/db
```

4. **Configure the dashboard**

```bash
cd ../dashboard
composer install
cp config/config.example.php config/config.php
# Edit config/config.php with your MongoDB connection string
```

5. **Start the collector**

```bash
cd ../collector
python collector.py
```

6. **Deploy an agent**

```bash
cd ../agent
python agent.py
```

7. **Serve the dashboard**

```bash
# Using PHP's built-in server for development:
cd ../dashboard
php -S localhost:8080
```

Open `http://localhost:8080` in your browser.

***

## Configuration

All configuration is managed through environment variables or config files:

| Parameter | File | Description |
|-----------|------|-------------|
| `MONGO_URI` | `config/config.php` | MongoDB connection string |
| `COLLECTOR_HOST` | `agent/config.yaml` | IP/hostname of the collector |
| `COLLECTOR_PORT` | `agent/config.yaml` | Collector listening port (default: `5140`) |
| `ALERT_RULES_PATH` | `collector/config.yaml` | Path to YAML alert rules file |
| `LOG_LEVEL` | `collector/config.yaml` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`) |

***

## Project Structure

```
netsentinel/
│
├── agent/                   # Python monitoring agents
│   ├── agent.py             # Main agent entry point
│   ├── modules/             # Detection modules (network, process, auth…)
│   │   ├── network_monitor.py
│   │   ├── process_monitor.py
│   │   └── auth_monitor.py
│   ├── config.yaml          # Agent configuration
│   └── requirements.txt
│
├── collector/               # Central event collector
│   ├── collector.py         # Ingestion & alert engine
│   ├── rules/               # YAML-based detection rules
│   └── config.yaml
│
├── dashboard/               # PHP web dashboard
│   ├── index.php            # Main dashboard view
│   ├── api/                 # REST API endpoints
│   ├── views/               # HTML templates
│   ├── assets/              # CSS / JS / Chart.js
│   └── config/
│       ├── config.example.php
│       └── config.php       # (git-ignored)
│
├── docs/                    # Dissertation documentation
│   └── architecture.md
│
├── tests/                   # Unit & integration tests
│
├── .gitignore
├── README.md
└── LICENSE
```

***

## Screenshots

> _Dashboard screenshots will be added here as the project develops._

***

## Roadmap

- [x] Core agent framework with pluggable modules
- [x] Central collector with MongoDB persistence
- [x] PHP dashboard with live event stream
- [ ] Role-based access control (RBAC) for dashboard
- [ ] Email / webhook alerting integrations
- [ ] Anomaly detection using statistical baselines
- [ ] Docker Compose deployment
- [ ] Agent auto-update mechanism
- [ ] Expanded detection rules library

***

## Contributing

This project is part of a university dissertation. Feedback and suggestions are welcome via Issues. Pull requests may be accepted after the submission deadline.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

***

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

***

<div align="center">
  Built as an Arden University  IT Dissertation Project — Manchester, England 🇬🇧
</div>
