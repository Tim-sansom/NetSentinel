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
 * @author Tim Sansom
 * @version 1.0
 * @date 2026
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
                    // Version tracking for auditability and release management
                    require_once __DIR__ . '/../includes/version.php';
                    echo get_version(); 
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
                require_once __DIR__ . '/../includes/version.php';
                echo get_version(); 
            ?>
        </p>
    </footer>

    </div> <!-- Closes .main-content wrapper -->

    <!-- ========================================================================= -->
    <!-- JAVASCRIPT: THEME PERSISTENCE (Dark/Light Mode) -->
    <!-- ========================================================================= -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const themeToggleBtn = document.getElementById('theme-toggle');
            const themeIcon = document.getElementById('theme-icon');
            
            if (themeToggleBtn && themeIcon) {
                // Helper to swap Bootstrap Icons based on current theme
                function updateIcon(theme) {
                    if (theme === 'dark') {
                        themeIcon.classList.remove('bi-moon-stars-fill');
                        themeIcon.classList.add('bi-sun-fill');
                    } else {
                        themeIcon.classList.remove('bi-sun-fill');
                        themeIcon.classList.add('bi-moon-stars-fill');
                    }
                }

                // Initialize icon state on page load to prevent visual mismatch
                const currentTheme = document.documentElement.getAttribute('data-bs-theme');
                updateIcon(currentTheme);

                // Handle user toggle click
                themeToggleBtn.addEventListener('click', function() {
                    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
                    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                    
                    // Apply theme to DOM and persist in localStorage 
                    // (Client-side only approach ensures zero database overhead for UX preferences)
                    document.documentElement.setAttribute('data-bs-theme', newTheme);
                    localStorage.setItem('netsentinel-theme', newTheme);
                    updateIcon(newTheme);
                });
            }
        });
    </script>
<?php endif; ?>
</body>
</html>