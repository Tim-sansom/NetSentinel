# NetSentinel Project Task Board

## Stage 1: Scope Lock (Planning)
- [x] Reconfirm MVP and freeze scope
- [x] Map FR/NFR/SR to specific development tasks
- [x] Set up task board (TODO.md)

## Stage 2: Agent Foundation
- [ ] Create project directory structure (`agent/`, `backend/`, `dashboard/`)
- [ ] Set up Python virtual environment and `requirements.txt`
- [ ] Build `config.py` and `logger.py`
- [ ] Build `api_client.py` (HTTPS POST logic)
- [ ] Build `agent.py` main execution loop (Skeleton)
- [ ] Send a hardcoded "test payload" to a mock API/Postman

## Stage 3: Core Checks (Python)
- [ ] Implement `SystemInfoCollector` (OS, version, uptime)
- [ ] Implement `PortCheck` (TCP sockets for RDP, SSH, SMB)
- [ ] Implement `FirewallCheck` (Windows Defender / UFW status)
- [ ] Implement `LatencyCheck` (Ping gateway/server)
- [ ] Integrate checks into the main `agent.py` runner

## Stage 4: API and Database (PHP/MySQL)
- [ ] Design and create MySQL schema (ERD implementation)
- [ ] Build `db.php` (PDO connection) and `auth.php` (Token validation)
- [ ] Build `POST /api/submit.php` (Receive and validate agent JSON)
- [ ] Build `GET /api/devices.php` (For dashboard polling)

## Stage 5: Dashboard v1 (Frontend)
- [ ] Build Bootstrap layout and Navigation
- [ ] Build Login page and PHP Session handling (Admin/Viewer)
- [ ] Build Devices Overview page (DataTables integration)
- [ ] Build Device Detail page (Chart.js integration for trends)
- [ ] Build Recent Alerts table

## Stage 6: Lab & Evaluation Setup
- [ ] Provision Proxmox VMs (1x LAMP, 1x Win10, 1x Ubuntu)
- [ ] Deploy backend to LAMP VM
- [ ] Deploy agents to endpoint VMs
- [ ] Define 4-6 test scenarios (e.g., open RDP, disabled firewall)
- [ ] Run evaluation and capture metrics (CPU/RAM/Latency)