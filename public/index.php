<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel - Enterprise Endpoint Security for SMEs | Open Source</title>
    <meta name="description" content="NetSentinel is a lightweight, open-source SIEM-style monitoring platform for SMEs. Deploy cross-platform agents, visualise threats in real-time. Free, MIT licensed.">
    
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
    
    <!-- Bootstrap 5.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    
    <!-- Custom Project Styles -->
    <link href="assets/css/style.css" rel="stylesheet">

    <!-- Favicons -->
    <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg">
    <link rel="alternate icon" type="image/png" href="assets/img/favicon.png">
    <link rel="apple-touch-icon" href="assets/img/favicon.png">
</head>
<body class="landing-page">
    <!-- WCAG: Skip to main content link for keyboard/screen reader users -->
    <a href="#main-content" class="visually-hidden-focusable position-absolute top-0 start-0 p-3 bg-primary text-white z-3">Skip to main content</a>

    <!-- Ambient Background -->
    <div class="ambient-bg"></div>
    
    <!-- Network Mesh Animation -->
    <div class="network-mesh" id="networkMesh"></div>

    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top" aria-label="Main navigation">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="bi bi-shield-check me-2"></i>NetSentinel
            </a>
            <!-- FIX 1: Added aria-label, aria-controls, and aria-expanded for accessibility -->
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item"><a class="nav-link" href="#features">Features</a></li>
                    <li class="nav-item"><a class="nav-link" href="#architecture">Architecture</a></li>
                    <li class="nav-item"><a class="nav-link" href="#pricing">Why NetSentinel</a></li>
                    <li class="nav-item">
                        <a class="nav-link" href="https://github.com/Tim-sansom/NetSentinel" target="_blank">
                            <i class="bi bi-github me-1"></i>GitHub
                        </a>
                    </li>
                    <li class="nav-item ms-lg-3">
                        <a class="btn btn-primary-glow" href="login.php">
                            <i class="bi bi-box-arrow-in-right me-2"></i>Login
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- FIX 3: Wrapped primary content in a <main> landmark for screen readers -->
    <main id="main-content">
        <!-- Hero Section -->
        <section class="hero">
            <div class="container">
                <div class="row align-items-center">
                    <div class="col-lg-7">
                        <div class="hero-badge">
                            <i class="bi bi-award-fill"></i>
                            <span>MIT Licensed • Open Source • UK Academic Project</span>
                        </div>
                        <h1>Enterprise Endpoint Security.<br><span class="gradient-text">Right-Sized for SMEs.</span></h1>
                        <p class="hero-subtitle">
                            NetSentinel is a lightweight, open-source SIEM-style monitoring platform. 
                            Deploy cross-platform Python agents, visualise your network topology, and detect threats in real-time. 
                            No bloat. No enterprise price tag. Just security that works.
                        </p>
                        <div class="hero-cta">
                            <a href="login.php" class="btn btn-primary-glow btn-lg">
                                <i class="bi bi-speedometer2 me-2"></i>Launch Dashboard
                            </a>
                            <a href="https://github.com/Tim-sansom/NetSentinel" target="_blank" class="btn btn-glass btn-lg">
                                <i class="bi bi-github me-2"></i>View on GitHub
                            </a>
                        </div>
                        <div class="mt-5 d-flex gap-4 flex-wrap">
                            <div class="stat-card">
                                <span class="stat-number">100%</span>
                                <div class="stat-label">Free & Open Source</div>
                            </div>
                            <div class="stat-card">
                                <span class="stat-number">£0</span>
                                <div class="stat-label">Licensing Costs</div>
                            </div>
                            <div class="stat-card">
                                <span class="stat-number">5min</span>
                                <div class="stat-label">Deployment Time</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-5 d-none d-lg-block">
                        <div class="glass-card hero-mockup">
                            <div class="text-center mb-4">
                                <i class="bi bi-hdd-network display-1 gradient-text"></i>
                            </div>
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <span class="text-secondary">Agent Status</span>
                                <span class="badge bg-success">4 Online</span>
                            </div>
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <span class="text-secondary">Health Score</span>
                                <span class="gradient-text fw-bold fs-5">87%</span>
                            </div>
                            <div class="d-flex justify-content-between align-items-center">
                                <span class="text-secondary">Active Threats</span>
                                <span class="badge bg-danger">0 Critical</span>
                            </div>
                            <div class="mt-4 pt-3 border-top border-glass">
                                <small class="text-secondary">
                                    <i class="bi bi-clock me-2"></i>Last scan: 2 minutes ago
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Cost Comparison Section -->
        <section id="pricing" class="section-padding">
            <div class="container">
                <div class="section-header">
                    <h2>Enterprise Power.<br><span class="gradient-text">SME Budget.</span></h2>
                    <p>Why pay £15,000+ per year when open-source delivers the same visibility?</p>
                </div>
                
                <div class="cost-comparison">
                    <div class="row g-4">
                        <div class="col-md-6">
                            <h3 class="mb-4 text-secondary">Traditional Enterprise SIEM</h3>
                            <!-- FIX 2: Changed h5 to h4 to maintain proper heading hierarchy under h3 -->
                            <div class="cost-item enterprise">
                                <div>
                                    <h4 class="mb-1">Annual Licensing</h4>
                                    <small class="text-secondary">Per endpoint + server costs</small>
                                </div>
                                <div class="price-tag enterprise">£5,000-£15,000<span class="price-suffix">/year</span></div>
                            </div>
                            <div class="cost-item enterprise">
                                <div>
                                    <h4 class="mb-1">Implementation</h4>
                                    <small class="text-secondary">Consultant fees & setup</small>
                                </div>
                                <div class="price-tag enterprise">£10,000+<span class="price-suffix"> one-time</span></div>
                            </div>
                            <div class="cost-item enterprise">
                                <div>
                                    <h4 class="mb-1">Training & Support</h4>
                                    <small class="text-secondary">Staff training required</small>
                                </div>
                                <div class="price-tag enterprise">£3,000+<span class="price-suffix">/year</span></div>
                            </div>
                            <div class="mt-4 p-3 rounded bg-rose-subtle border-rose">
                                <strong class="text-rose">Total Year 1 Cost: £18,000-£28,000+</strong>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <h3 class="mb-4 gradient-text">NetSentinel</h3>
                            <!-- FIX 2: Changed h5 to h4 to maintain proper heading hierarchy under h3 -->
                            <div class="cost-item netsentinel">
                                <div>
                                    <h4 class="mb-1">Software Licensing</h4>
                                    <small class="text-secondary">MIT License - forever free</small>
                                </div>
                                <div class="price-tag netsentinel">£0<span class="price-suffix"> forever</span></div>
                            </div>
                            <div class="cost-item netsentinel">
                                <div>
                                    <h4 class="mb-1">Infrastructure</h4>
                                    <small class="text-secondary">Run on existing hardware or £5/mo VPS</small>
                                </div>
                                <div class="price-tag netsentinel">£0-£60<span class="price-suffix">/year</span></div>
                            </div>
                            <div class="cost-item netsentinel">
                                <div>
                                    <h4 class="mb-1">Support</h4>
                                    <small class="text-secondary">Community + documentation</small>
                                </div>
                                <div class="price-tag netsentinel">£0<span class="price-suffix"> free</span></div>
                            </div>
                            <div class="mt-4 p-3 rounded bg-emerald-subtle border-emerald">
                                <strong class="text-emerald">Total Year 1 Cost: £0-£60</strong>
                                <div class="small mt-1 text-emerald">
                                    <i class="bi bi-check-circle me-1"></i>Save £17,940+ compared to enterprise
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Features Section -->
        <section id="features" class="section-padding">
            <div class="container">
                <div class="section-header">
                    <h2>Built for Modern<br><span class="gradient-text">Hybrid Workforces</span></h2>
                    <p>Lightweight agents, powerful insights. Deploy across Windows, Linux, and macOS endpoints in minutes.</p>
                </div>
                
                <div class="row g-4">
                    <!-- FIX 2: Changed h4 to h3 to maintain proper heading hierarchy under h2 -->
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-laptop"></i></div>
                            <h3>Cross-Platform Agents</h3>
                            <p class="text-secondary">Python-based agents running natively on Windows, Ubuntu, and macOS. No complex dependencies.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-graph-up-arrow"></i></div>
                            <h3>Live SOC Dashboard</h3>
                            <p class="text-secondary">Real-time KPIs, threat trends, and health scores. Visualise your entire endpoint fleet at a glance.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-diagram-3"></i></div>
                            <h3>Network Topology</h3>
                            <p class="text-secondary">Auto-discovered device mapping with Cytoscape.js visualisation. See your network come alive.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-shield-check"></i></div>
                            <h3>Threat Detection</h3>
                            <p class="text-secondary">Automated port scanning, firewall checks, and configuration auditing. Detect misconfigurations early.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-code-slash"></i></div>
                            <h3>100% Open Source</h3>
                            <p class="text-secondary">MIT licensed. Audit the code. Modify it. Deploy it anywhere. No black-box algorithms or vendor lock-in.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-server"></i></div>
                            <h3>LAMP Compatible</h3>
                            <p class="text-secondary">Runs on standard LAMP hosting. Deploy on university servers, cPanel hosting, or your own Proxmox lab.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-lightning-charge"></i></div>
                            <h3>Lightweight</h3>
                            <p class="text-secondary">Minimal resource overhead. Agents use &lt;5% CPU. Perfect for SME infrastructure constraints.</p>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-3">
                        <div class="glass-card">
                            <div class="feature-icon"><i class="bi bi-key"></i></div>
                            <h3>Secure by Design</h3>
                            <p class="text-secondary">HTTPS transport, agent authentication, role-based access, and comprehensive audit logging.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Architecture Section -->
        <section id="architecture" class="section-padding">
            <div class="container">
                <div class="section-header">
                    <h2>Simple.<br><span class="gradient-text">Elegant Architecture.</span></h2>
                    <p>Three components working together to deliver enterprise-grade visibility.</p>
                </div>
                
                <div class="arch-diagram">
                    <div class="arch-box">
                        <i class="bi bi-laptop display-4 gradient-text mb-3 d-block"></i>
                        <!-- FIX 2: Changed h5 to h4 to maintain proper heading hierarchy under h2 -->
                        <h4>Endpoint Agent</h4>
                        <p class="text-secondary small mb-0">Python 3.10+<br>Scheduled checks<br>HTTPS submission</p>
                    </div>
                    <div class="arch-arrow"><i class="bi bi-arrow-right"></i></div>
                    <div class="arch-box">
                        <i class="bi bi-code-slash display-4 gradient-text mb-3 d-block"></i>
                        <h4>PHP API Backend</h4>
                        <p class="text-secondary small mb-0">PHP 8.2 REST API<br>Auth & validation<br>MySQL 8 storage</p>
                    </div>
                    <div class="arch-arrow"><i class="bi bi-arrow-right"></i></div>
                    <div class="arch-box">
                        <i class="bi bi-speedometer2 display-4 gradient-text mb-3 d-block"></i>
                        <h4>Dashboard</h4>
                        <p class="text-secondary small mb-0">Bootstrap 5 + Chart.js<br>Real-time visualisation<br>DataTables integration</p>
                    </div>
                </div>
                
                <div class="row mt-5 g-4">
                    <div class="col-md-4">
                        <div class="glass-card text-center">
                            <h5 class="gradient-text mb-3">Technology Stack</h5>
                            <ul class="list-unstyled text-start text-secondary small">
                                <li class="mb-2"><i class="bi bi-check2 text-emerald me-2"></i>Python 3.10+ (Agent)</li>
                                <li class="mb-2"><i class="bi bi-check2 text-emerald me-2"></i>PHP 8.2 (Backend)</li>
                                <li class="mb-2"><i class="bi bi-check2 text-emerald me-2"></i>MySQL 8 (Database)</li>
                                <li class="mb-2"><i class="bi bi-check2 text-emerald me-2"></i>Bootstrap 5.3 (UI)</li>
                                <li class="mb-2"><i class="bi bi-check2 text-emerald me-2"></i>Chart.js / Cytoscape.js</li>
                            </ul>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="glass-card text-center">
                            <h5 class="gradient-text mb-3">Deployment Options</h5>
                            <ul class="list-unstyled text-start text-secondary small">
                                <li class="mb-2"><i class="bi bi-hdd text-cyan me-2"></i>Proxmox VM (Full control)</li>
                                <li class="mb-2"><i class="bi bi-cloud text-cyan me-2"></i>Standard cPanel hosting</li>
                                <li class="mb-2"><i class="bi bi-box text-cyan me-2"></i>Docker containers (Planned)</li>
                                <li class="mb-2"><i class="bi bi-shield-check text-emerald me-2"></i>Let's Encrypt SSL</li>
                            </ul>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="glass-card text-center">
                            <h5 class="gradient-text mb-3">Security Features</h5>
                            <ul class="list-unstyled text-start text-secondary small">
                                <li class="mb-2"><i class="bi bi-lock text-emerald me-2"></i>HTTPS/TLS 1.3</li>
                                <li class="mb-2"><i class="bi bi-key text-emerald me-2"></i>Per-agent authentication</li>
                                <li class="mb-2"><i class="bi bi-people text-emerald me-2"></i>Role-based access control</li>
                                <li class="mb-2"><i class="bi bi-journal-text text-emerald me-2"></i>Comprehensive audit logs</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- CTA Section -->
        <section class="section-padding">
            <div class="container">
                <div class="glass-card text-center py-5 cta-card">
                    <h2 class="mb-3">Ready to Secure Your<br><span class="gradient-text">Hybrid Workforce?</span></h2>
                    <p class="text-secondary fs-5 mb-4 mx-auto" style="max-width: 700px;">
                        Join the growing number of SMEs and security professionals using NetSentinel for lightweight, effective endpoint monitoring.
                    </p>
                    <div class="d-flex gap-3 justify-content-center flex-wrap">
                        <a href="login.php" class="btn btn-primary-glow btn-lg">
                            <i class="bi bi-box-arrow-in-right me-2"></i>Get Started - It's Free
                        </a>
                        <a href="https://github.com/Tim-sansom/NetSentinel" target="_blank" class="btn btn-glass btn-lg">
                            <i class="bi bi-github me-2"></i>Star on GitHub
                        </a>
                    </div>
                    <div class="mt-5 pt-4 border-top border-glass">
                        <p class="text-secondary mb-0">
                            <i class="bi bi-mortarboard me-2"></i>
                            Undergraduate Dissertation Project • Arden University • MIT Licensed
                        </p>
                    </div>
                </div>
            </div>
        </section>
    </main> <!-- End of main content landmark -->

    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="footer-links">
                <a href="https://github.com/Tim-sansom/NetSentinel" target="_blank"><i class="bi bi-github me-1"></i>GitHub Repository</a>
                <a href="login.php"><i class="bi bi-box-arrow-in-right me-1"></i>Login</a>
                <a href="register.php"><i class="bi bi-person-plus me-1"></i>Register</a>
                <a href="#"><i class="bi bi-file-earmark-text me-1"></i>Documentation</a>
            </div>
            <p class="mb-1 small">© 2026 NetSentinel • SME Endpoint Monitoring Prototype • Developed by Tim Sansom</p>
            <p class="mb-0 x-small text-secondary">MIT Licensed • Open Source • Built for Arden University Dissertation</p>
        </div>
    </footer>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Generate Network Mesh Animation
        function createNetworkMesh() {
            const mesh = document.getElementById('networkMesh');
            if (!mesh) return;
            const nodeCount = 30;
            for (let i = 0; i < nodeCount; i++) {
                const node = document.createElement('div');
                node.className = 'mesh-node';
                node.style.left = Math.random() * 100 + '%';
                node.style.top = Math.random() * 100 + '%';
                node.style.animationDelay = Math.random() * 20 + 's';
                node.style.animationDuration = (15 + Math.random() * 10) + 's';
                mesh.appendChild(node);
            }
        }
        createNetworkMesh();
        
        // Navbar scroll effect
        window.addEventListener('scroll', function() {
            const navbar = document.querySelector('.navbar');
            if (window.scrollY > 50) {
                navbar.style.background = 'rgba(15, 23, 42, 0.95)';
                navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.3)';
            } else {
                navbar.style.background = 'rgba(15, 23, 42, 0.8)';
                navbar.style.boxShadow = 'none';
            }
        });
        
        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    </script>
</body>
</html>