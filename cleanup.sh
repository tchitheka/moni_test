#!/bin/bash
cd ~/monitoring-stack

echo "Cleaning up runtime files..."
rm -rf grafana/csv grafana/pdf grafana/png grafana/plugins grafana/unified-search
rm -f grafana/grafana.db
rm -rf monitoring-stack
rm -f grafana/provisioning/*/sample.yaml
rm -f grafana/provisioning/dashboards/sample.yaml
rm -f grafana/provisioning/datasources/sample.yaml

echo "Creating missing Dockerfile.grafana..."
cat > Dockerfile.grafana << 'EOF'
FROM grafana/grafana:latest
COPY grafana/provisioning /etc/grafana/provisioning
COPY grafana/grafana.ini /etc/grafana/grafana.ini
EXPOSE 3000
EOF

echo "Verifying directory structure..."
tree -L 3

echo "Cleanup complete! Now run: docker-compose up --build -d"
