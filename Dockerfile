FROM php:8.3-apache

# Install system dependencies, MySQL client, and Cron
RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg-dev libfreetype6-dev \
    zip unzip git cron mariadb-client \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions required by NetSentinel
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd pdo pdo_mysql

# Enable Apache mod_rewrite for clean URLs
RUN a2enmod rewrite

# Set Apache DocumentRoot to the /public folder (Security Best Practice)
ENV APACHE_DOCUMENT_ROOT /var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Setup the Cron Job for the CISA Threat Feed directly in the image
RUN echo "0 */6 * * * cd /var/www/html && /usr/local/bin/php /var/www/html/cronjobs/update_threat_feed.php >> /var/log/cron.log 2>&1" | crontab -

# Start Cron in the background, then start Apache in the foreground
CMD ["sh", "-c", "service cron start && apache2-foreground"]