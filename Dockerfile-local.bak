FROM php:8.3-apache

# Install Python 3 AND the network tools required for the discovery script
RUN apt-get update && apt-get install -y \
    python3 \
    iputils-ping \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql

# Enable Apache modules
RUN a2enmod rewrite
RUN a2enmod ssl