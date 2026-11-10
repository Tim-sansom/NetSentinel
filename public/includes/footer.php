
<?php
/**
 * NetSentinel - Global Footer & Layout Closure Template
 * ================================================================================
 * 
 * PURPOSE:
 * Serves as the structural closure for the NetSentinel dashboard and public pages.
 * It handles semantic HTML landmark closure, version tracking, and client-side 
 * theme persistence (Dark/Light mode).
 * 
 * ACADEMIC SIGNIFICANCE:
 * Demonstrates attention to UX consistency and accessibility (WCAG).
 * By separating public and authenticated layouts, it ensures a clean visual 
 * boundary between the SaaS landing/auth pages and the internal monitoring dashboard.
 * 
 */

// $current_page and $is_public_page variables are inherited from header.php
?>

<?php if ($is_public_page): ?>
    <!-- ========================================================================= -->
    <!-- PUBLIC PAGE FOOTER (Login, Register, etc.) -->
    <!-- ========================================================================= -->
    </div> <!-- Closes .container for public pages -->
    
    <!-- Simple Footer for Public Pages -->
    <footer class="mt-5 py-3 bg-white border-top">
        <div class="container text-center text-muted">
            <small>
                &copy; <?php echo date('Y'); ?> NetSentinel - SME Endpoint Monitoring Prototype Developed By Tim Sansom v<?php 
                    if (file_exists(__DIR__ . '/../includes/version.php')) {
                        require_once __DIR__ . '/../includes/version.php';
                        echo function_exists('get_version') ? get_version() : '1.0.0';
                    } else {
                        echo '1.0.0';
                    }
                ?>
            </small>
        </div>
    </footer>

<?php else: ?>
    <!-- ========================================================================= -->
    <!-- DASHBOARD FOOTER (Authenticated Users) -->
    <!-- ========================================================================= -->
    </main> <!-- Closes the <main id="main-content"> landmark opened in header.php -->

    <!-- NFR4 (Accessibility): Semantic footer with ARIA role for screen readers -->
    <footer class="app-footer" role="contentinfo">
        <p class="mb-0">
            &copy; <?php echo date('Y'); ?> NetSentinel - SME Endpoint Monitoring Prototype Developed By Tim Sansom v<?php 
                if (file_exists(__DIR__ . '/../includes/version.php')) {
                    require_once __DIR__ . '/../includes/version.php';
                    echo function_exists('get_version') ? get_version() : '1.0.0';
                } else {
                    echo '1.0.0';
                }
            ?>
        </p>
    </footer>

    </div> <!-- Closes .main-content wrapper -->

    <!-- ========================================================================= -->
    <!-- JAVASCRIPT: GLOBAL TOOLTIPS, THEME PERSISTENCE & MOBILE SIDEBAR TOGGLE -->
    <!-- ========================================================================= -->
    <script>
    // Initialize tooltips globally - runs after DOM is fully loaded
    function initializeTooltips() {
        // Check if Bootstrap is loaded
        if (typeof bootstrap === 'undefined') {
            console.error(' Bootstrap not loaded! Cannot initialize tooltips.');
            return false;
        }
        
        // Find all elements with tooltip attribute
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        
        // Initialize each tooltip
        const tooltipList = [].slice.call(tooltipTriggerList).map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, { 
                trigger: 'hover', 
                placement: 'auto',
                delay: { show: 100, hide: 50 }
            });
        });
        
        console.log(`✅ Initialized ${tooltipList.length} Bootstrap tooltips globally`);
        return true;
    }
    
    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            // Small delay to ensure Bootstrap is fully loaded
            setTimeout(initializeTooltips, 100);
            
            // Also initialize other components
            initializeThemeToggle();
            initializeMobileSidebar();
        });
    } else {
        // DOM already loaded
        setTimeout(initializeTooltips, 100);
        initializeThemeToggle();
        initializeMobileSidebar();
    }
    
    // Theme Toggle Function
    function initializeThemeToggle() {
        const themeToggleBtn = document.getElementById('theme-toggle');
        const themeIcon = document.getElementById('theme-icon');
        
        if (themeToggleBtn && themeIcon) {
            function updateIcon(theme) {
                if (theme === 'dark') {
                    themeIcon.classList.remove('bi-moon-stars-fill');
                    themeIcon.classList.add('bi-sun-fill');
                } else {
                    themeIcon.classList.remove('bi-sun-fill');
                    themeIcon.classList.add('bi-moon-stars-fill');
                }
            }

            const currentTheme = document.documentElement.getAttribute('data-bs-theme');
            updateIcon(currentTheme);

            themeToggleBtn.addEventListener('click', function() {
                const currentTheme = document.documentElement.getAttribute('data-bs-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                
                document.documentElement.setAttribute('data-bs-theme', newTheme);
                localStorage.setItem('netsentinel-theme', newTheme);
                updateIcon(newTheme);
            });
        }
    }
    
    // Mobile Sidebar Toggle Function
    function initializeMobileSidebar() {
        const sidebarToggle = document.getElementById('sidebarToggle');
        const sidebar = document.getElementById('mainSidebar');
        
        if (sidebarToggle && sidebar) {
            sidebarToggle.addEventListener('click', function(e) {
                e.preventDefault();
                sidebar.classList.toggle('mobile-open');
            });

            document.addEventListener('click', function(event) {
                if (window.innerWidth < 768) {
                    if (!sidebar.contains(event.target) && !sidebarToggle.contains(event.target)) {
                        sidebar.classList.remove('mobile-open');
                    }
                }
            });
        }
    }
    
    // Re-initialize tooltips after AJAX content loads (for DataTables, etc.)
    document.addEventListener('DOMNodeInserted', function(e) {
        if (e.target.querySelectorAll && e.target.querySelectorAll('[data-bs-toggle="tooltip"]').length > 0) {
            setTimeout(initializeTooltips, 50);
        }
    });
    </script>
<?php endif; ?>
</body>
</html>