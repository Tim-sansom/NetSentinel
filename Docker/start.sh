#!/bin/bash

# 1. Setup the Cron Job for the CISA Threat Feed
# Runs every 6 hours (0 */6 * * *)
echo "0 */6 * * * cd /var/www/html && /usr/local/bin/php /var/www/html/cronjobs/update_threat_feed.php >> /var/log/cron.log 2>&1" | crontab -

# 2. Start the Cron service in the background
service cron start

# 3. Start Apache in the foreground (keeps the container alive)
apache2-foreground