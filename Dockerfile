FROM ubuntu:22.04

LABEL maintainer="security-research"
LABEL description="php2shell CVE-2026-109618/109619 — Vulnerable PHP lab"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common \
        gnupg2 \
        curl \
        ca-certificates \
    && add-apt-repository ppa:ondrej/php -y \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        php8.4-fpm \
        php8.4-cli \
        php8.4-common \
        php8.4-mbstring \
        php8.4-xml \
        nginx \
        supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i 's|listen = /run/php/php8.4-fpm.sock|listen = 127.0.0.1:9000|' \
        /etc/php/8.4/fpm/pool.d/www.conf \
    && mkdir -p /var/lib/php/sessions \
    && chmod 1733 /var/lib/php/sessions \
    && chown www-data:www-data /var/lib/php/sessions \
    && mkdir -p /run/php

COPY php.ini             /etc/php/8.4/fpm/php.ini
COPY nginx.conf          /etc/nginx/sites-available/default
COPY supervisord.conf    /etc/supervisor/conf.d/app.conf
COPY www/                /var/www/html/

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
    CMD curl -sf http://localhost/index.php > /dev/null || exit 1

CMD ["/usr/bin/supervisord", "-n"]
