# NetSentinel
<div align="center">

[![PHP Version](https://img.shields.io/badge/PHP-8.3-777BB4?style=for-the-badge&logo=php&logoColor=white)](https://www.php.net/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-00758F?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<img src="https://user-gen-media-assets.s3.amazonaws.com/gpt4o_images/22fc0602-2220-41f9-ac4e-1736934532a0.png" alt="NetSentinel logo" width="180">

# 🛡️ NetSentinel

### Lightweight SIEM — Real-Time Network Threat Detection & Dashboard







> A lightweight, modular Security Information and Event Management (SIEM) system built as a university dissertation project. NetSentinel combines cross-platform Python monitoring agents with a real-time PHP/MySQL web dashboard to detect, log, and visualise endpoint security health and network threats.

</div>
## 🖼️ Visual Showcase

<div align="center">

<details>
<summary><strong>Click to expand the application gallery</strong></summary>
<br>

<table>
  <tr>
    <td align="center">
      <img src="screenshots/Security Overview - NetSentinel.png" alt="Netsentinel Dashboard" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px;">
      <br><em>Network topology, health metrics, and active threat indicators</em>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="screenshots/Endpoint Devices - NetSentinel.png" alt="Devicess Page" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>View and manage all monitored devices in your network</em>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="screenshots/Recent Alerts - NetSentinel.png" alt="Alets Page" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Review and prioritize potential security risks on your endpoints</em>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="screenshots/Anomalies & Risks - NetSentinel.png" alt="Anomalies & Risks Page" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Identify potential security issues before they become breaches</em>
    </td>
  </tr>
   <tr>
    <td align="center">
      <img src="screenshots/Network Discovery - NetSentinel.png" alt="Network Discovery" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Adaptive scanning with historical delta tracking</em>
    </td>
  </tr>
   <tr>
    <td align="center">
      <img src="screenshots/Threat Intelligence - NetSentinel.png" alt="Threat Intelligence" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Track known exploited vulnerabilities to prioritize your patching efforts</em>
    </td>
  </tr>
   <tr>
    <td align="center">
      <img src="screenshots/Policy Management - NetSentinel.png" alt="Policy Management" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Organise endpoints and automate security compliance checks</em>
    </td>
  </tr>
   <tr>
    <td align="center">
      <img src="screenshots/Audit Logs - NetSentinel.png" alt="Audit Logs" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Track user activity, system changes, and security events for compliance</em>
    </td>
  </tr>
   <tr>
    <td align="center">
      <img src="screenshots/User Audit - NetSentinel.png" alt="User Audit" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Admin user audit area to edit and delete end users</em>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="screenshots/Server Telemetry - NetSentinel.png" alt="Server Telemetry" style="border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); width: 100%; max-width: 800px; margin-top: 20px;">
      <br><em>Server Telemetry and stats.</em>
    </td>
  </tr>
</table>

</details>

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

NetSentinel is a university dissertation project that implements a lightweight SIEM (Security Information and Event Management) solution designed for resource-constrained SME environments. Unlike enterprise SIEM platforms, NetSentinel focuses on simplicity, extensibility, and real-time visibility.

The system operates through distributed **Python agents** that monitor host security posture (ports, firewall, patches, latency) and forward structured JSON telemetry to a central **PHP/MySQL backend**. A **Bootstrap-powered web dashboard** provides analysts with live device health, alert management, and threat intelligence visualisations.

***

## Features

- 🔍 **Real-Time Event Monitoring** — Lightweight agents continuously capture system and network events
- 🚨 **Alerting Engine** — Rule-based alert generation for common threat signatures (port scans, brute force, suspicious processes)
- 📊 **Interactive Dashboard** — PHP/HTML5 frontend for live event stream, alert triaging, and statistics
- 🗄️ MySQL Storage — Normalised relational schema with Row-Level Security (RLS) for multi-tenant isolation
- 🤖 **Modular Agent Design** — Plug-in architecture allows new detection modules to be added without modifying core code
- 🌐 **Multi-Host Support** — Agents can be deployed across multiple hosts, all reporting to a central collector
- 📈 **Visualisations** — Charts and graphs for event trends, top talkers, and alert severity distribution
- 🔐 **Severity Classification** — Events tagged LOW / MEDIUM / HIGH / CRITICAL with colour-coded dashboard indicators

***

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        NetSentinel                              │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐     │
│  │  Endpoint 1  │   │  Endpoint 2  │   │  Endpoint N...   │     │
│  │ (Python Agent│   │ (Python Agent│   │ (Python Agent)   │     │
│  └──────┬───────┘   └──────┬───────┘   └────────┬─────────┘     │
│         │                  │                     │              │
│         └──────────────────┼─────────────────────┘              │
│                            │ HTTPS JSON (Telemetry)             │
│                     ┌──────▼──────┐                             │
│                     │  PHP API    │                             │
│                     │ (submit.php)│                             │
│                     └──────┬──────┘                             │
│                            │                                    │
│                     ┌──────▼──────┐                             │
│                     │   MySQL 8   │                             │
│                     │  (Database) │                             │
│                     └──────┬──────┘                             │
│                            │                                    │
│                     ┌──────▼──────┐                             │
│                     │  Dashboard  │                             │
│                     │ (PHP/HTML5) │                             │
│                     └─────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

***

## Tech Stack

| Component               | Technology.         | Purpose.                                    |
| :---------------------- | :------------------ | :------------------------------------------ |
| **Monitoring Agents**   | Python 3.10+        | Host & network event collection             |
| **Backend API**         | PHP 8.3             | REST API & server-side logic                |
| **Database**            | MySQL 8.0           | Telemetry, device tracking, and user data   |
| **Dashboard Frontend**  | Bootstrap 5 / HTML5 | Responsive UI and layout                    |
| **Visualisations**      | Chart.js            | Line/bar charts for trends and metrics      |
| **Data Tables**         | DataTables.js       | Sortable/filterable device and alert tables |
| **Threat Feed**         | CISA KEV (JSON)     | Live vulnerability intelligence             |

***



## Getting Started (Manual LAMP)

If you prefer to run NetSentinel on a native Linux server (e.g., Ubuntu/Debian):

### Prerequisites
- Apache 2.4+
- PHP 8.3+ (with `pdo_mysql`, `gd`, `zip` extensions)
- MySQL 8.0+
- Python 3.10+ (for agents)

### Installation Steps

1. **Clone and Setup Web Root:**
   ```bash
   git clone https://github.com/Tim-sansom/NetSentinel.git /var/www/html/netsentinel

2. Configure Apache:
Set your DocumentRoot to /var/www/html/netsentinel/public.

  ```bash
   sudo a2enmod rewrite
   sudo systemctl restart apache2

3. Database Setup:
  Create a MySQL database and user, then import the schema from db-init/init.sql.
  Update public/includes/db.php with your credentials.

4. Install Agent Dependencies (on endpoints):
   pip install requests psutil schedule python-dotenv

***

## Project Structure

```
netsentinel/
│
├── agent/ # Python monitoring agents
│ ├── agent.py # Main agent entry point
│ ├── checks/ # Detection modules (port, firewall, patch…)
│ ├── config.py # Agent configuration manager
│ └── api_client.py # HTTPS communication handler
│
├── public/ # PHP Web Dashboard (DocumentRoot)
│ ├── index.php # Main dashboard view
│ ├── api/ # REST API endpoints (submit.php, stats.php)
│ ├── includes/ # Core logic (db.php, auth.php, audit.php)
│ └── assets/ # CSS / JS / Chart.js
│
├── cronjobs/ # Background maintenance scripts
│ └── update_threat_feed.php # CISA KEV ingester
│
├── docker/ # Containerization files
│ ├── Dockerfile
│ ├── docker-compose.yml
│ └── start.sh
│
├── db-init/ # Database schema initialization
│
├── docs/ # Dissertation documentation
│
└── README.md
```

***
### Docker

```

🚀 Getting Started (Docker)
The recommended way to run NetSentinel is via Docker Compose. This abstracts away the LAMP stack configuration and ensures a reproducible environment.
Prerequisites
Docker Desktop installed and running.

**Quick Start**

1. **Clone the repository:**

     git clone https://github.com/Tim-sansom/NetSentinel.git
   cd netsentinel

2. **Configure Environment:**
Copy the example environment file. You can edit it to change default passwords if desired.

     cp .env.example .env

3. **Start the Stack:**
Build and launch the containers (Web, MySQL, and Worker).

    docker-compose up -d --build

4. **Access the Dashboard:**

  Open your browser and navigate to:

    👉 http://localhost:8080 (or the port specified in your docker-compose.yml)

## Configuration

All sensitive configuration is managed through environment variables or `.env` files.

| Parameter             | File              | Description                                              |
| :---------------------| :---------------- | :------------------------------------------------------- |
| `DB_HOST`             | `.env` / `db.php` | MySQL hostname (default: `localhost` or `db` for Docker) |
| `DB_NAME`             | `.env` / `db.php` | Database name                                            |
| `DB_USER`             | `.env` / `db.php` | Database username                                        |
| `DB_PASS`             | `.env` / `db.php` | Database password                                        |
| `NETSENTINEL_API_URL` | `agent/.env`      | URL where agents send telemetry                          |

```
***

## Roadmap

- [x] Core agent framework with pluggable modules
- [x] PHP/MySQL backend with REST API
- [x] Bootstrap dashboard with live event stream
- [x] Role-based access control (RBAC) & Row-Level Security
- [x] CISA KEV Threat Intelligence integration
- [x] Cross-platform agent support (Windows/Linux/macOS)
- [x] Docker Compose deployment
- [ ] Email / webhook alerting integrations
- [ ] Agent auto-update mechanism

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
