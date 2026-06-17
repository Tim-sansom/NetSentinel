FROM php:8.3-apache

# Install the PDO MySQL driver required for database connections
RUN docker-php-ext-install pdo pdo_mysql

# Enable Apache mod_rewrite (good practice for PHP routing)
RUN a2enmod rewrite