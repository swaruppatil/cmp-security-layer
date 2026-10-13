# Prometheus with its config baked in (Docker Desktop here cannot bind-mount ~/Desktop).
FROM prom/prometheus:v2.53.2
COPY prometheus.yml /etc/prometheus/prometheus.yml
ENTRYPOINT ["/bin/sh", "-c", "printf %s \"$ADMIN_API_KEY\" > /prometheus/admin_key && exec /bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --storage.tsdb.retention.time=7d"]
