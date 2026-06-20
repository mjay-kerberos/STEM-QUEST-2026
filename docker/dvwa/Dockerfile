# Thin wrapper around the official DVWA image.
# The upstream image symlinks /var/log/apache2/access.log → /dev/stdout,
# which means the host can never see the file through a volume mount.
# We replace the symlinks with real files (still tee'd to stdout via Apache's
# CustomLog) so the AI analyst can tail them in real time.

FROM ghcr.io/digininja/dvwa:latest

USER root

# Remove the symlinks and pre-create real log files.
RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log \
          /var/log/apache2/other_vhosts_access.log && \
    touch  /var/log/apache2/access.log /var/log/apache2/error.log && \
    chown  www-data:www-data /var/log/apache2/access.log /var/log/apache2/error.log

# Tee Apache logs to stdout/stderr too so `docker logs` still works.
RUN printf '%s\n' \
    'CustomLog "|/bin/cat" combined' \
    'ErrorLog  "|/bin/cat"' \
    > /etc/apache2/conf-enabled/zz-workshop-logs.conf

# Make sure www-data can write to /var/log/apache2 on volume-mounted dirs.
RUN chmod 0775 /var/log/apache2

# Upstream image's CMD already starts Apache; inherit it.
