</main> <!-- Closes the <main> tag opened in header.php -->

<footer class="bg-dark text-light text-center py-3 mt-5 border-top border-secondary">
    <div class="container">
        <small>
            &copy; <?php echo date('Y'); ?> NetSentinel - SME Endpoint Monitoring Prototype Developed By Tim Sansom v1.0.0
        </small>
    </div>
</footer>

<!-- PERFORMANCE NOTE (NFR1): No duplicate JS scripts are loaded here. 
     All libraries (Bootstrap, jQuery, DataTables) are loaded in the <head> 
     to prevent redundant network requests and ensure page-level inline scripts work. -->
</body>
</html>