        </main> <!-- Closes the <main> tag opened in header.php -->

        <!-- Footer inside the right-hand section -->
        <footer class="app-footer">
            <p class="mb-0">
                &copy; <?php echo date('Y'); ?> NetSentinel - SME Endpoint Monitoring Prototype Developed By Tim Sansom v<?php 
                    // Include version tracker and display current version
                    require_once __DIR__ . '/../includes/version.php';
                    echo get_version(); 
                ?>
            </p>
        </footer>

    </div> <!-- Closes .main-content -->

    <!-- Dark/Light Mode Toggle Logic -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
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
        });
    </script>
</body>
</html>