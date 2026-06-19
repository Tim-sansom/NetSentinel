NetSentinel Project Task Board

Stage 1: Scope Lock (Planning)
[x] Reconfirm MVP and freeze scope
[x] Map FR/NFR/SR to specific development tasks
[x] Set up task board (TODO.md)

Stage 2: Agent Foundation
[x] Create project directory structure (`agent/`, `backend/`, `dashboard/`)
[x] Set up Python virtual environment and `requirements.txt`
[x] Build `config.py` and `logger.py`
[x] Build `api_client.py` (HTTPS POST logic)
[x] Build `agent.py` main execution loop (Skeleton)
[x] Send a hardcoded "test payload" to a mock API/Postman

Stage 3: Core Checks (Python)
[x] Implement `SystemInfoCollector` (OS, version, uptime)
[x] Implement `PortCheck` (TCP sockets for RDP, SSH, SMB)
[x] Implement `FirewallCheck` (Windows Defender / UFW status)
[x] Implement `LatencyCheck` (Ping gateway/server)
[x] Integrate checks into the main `agent.py` runner

Stage 4: API and Database (PHP/MySQL)
[x] Design and create MySQL schema (ERD implementation)
[x] Build `db.php` (PDO connection) and `auth.php` (Token validation)
[x] Build `POST /api/submit.php` (Receive and validate agent JSON)
[x] Build `GET /api/devices.php` (For dashboard polling)

Stage 5: Dashboard v1 (Frontend)
[x] Set up dashboard directory structure (`public/`, `views/`, `includes/`, `assets/`)
[x] Build base Bootstrap layout (Header, Footer, Nav)
[x] Build Login page and PHP Session handling (Admin/Viewer roles)
[x] Build session middleware (protect dashboard routes)
[x] Build Devices Overview page (DataTables integration)
[x] Build Device Detail page (Chart.js integration for trends)
[x] Build Recent Alerts / Findings table
[x] Implement auto-refresh / AJAX polling for live updates

Stage 6: Lab & Evaluation Setup
[ ] Provision Proxmox VMs (1x LAMP, 1x Win10, 1x Ubuntu)
[ ] Deploy backend to LAMP VM
[ ] Deploy agents to endpoint VMs
[ ] Define 4-6 test scenarios (e.g., open RDP, disabled firewall)
[ ] Run evaluation and capture metrics (CPU/RAM/Latency)

Stage 7: Agent Expansion & Cross-Platform Testing
[ ] Expand remaining agent checks (if MVP stable)
[ ] Test and refine agent on Windows VM
[ ] Test and refine agent on Linux VM
[ ] Test and refine agent on macOS VM (if applicable/stretch)

Stage 8: Hardening & Security
[ ] Add API rate limiting
[ ] Improve logging and error handling (Agent & Backend)
[ ] Check role-based access control (RBAC) on dashboard
[ ] Basic security review (OWASP top 10 checks)

Stage 9: Integration Testing
[ ] Run full end-to-end pipeline test
[ ] Fix integration issues (Agent -> API -> DB -> Dashboard)
[ ] Capture screenshots and technical notes

Stage 10: Evaluation Execution
[ ] Finalize test scenarios and lab snapshots
[ ] Prepare results/metrics sheet
[ ] Measure latency and resource use (Endpoints & Server)
[ ] Run scenarios and record findings

Stage 11: Evidence Capture & Documentation
[ ] Export logs and SQL data for appendix
[ ] Save screenshots and evidence
[ ] Organise dissertation appendix evidence

Stage 12: Final Build Polish & Submission
[ ] Fix final bugs
[ ] Clean code, add comments, and update README
[ ] Prepare final build handover (ZIP/Git tag)
[ ] SUBMISSION