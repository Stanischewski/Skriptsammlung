#!/bin/bash
################################################################################
# Prometheus Exporters Installation Script für Proxmox VE
# 
# Installiert:
# - node_exporter (System-Metriken)
# - pve_exporter (Proxmox-spezifische Metriken)
#
# Autor: Sebastian Stanischewski
# Projekt: Netzwerk-Monitoring
# Datum: 13.10.2025
################################################################################

set -e  # Exit bei Fehler

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Versionen (anpassbar)
NODE_EXPORTER_VERSION="1.8.2"
PVE_EXPORTER_VERSION="3.4.4"

# Konfiguration
NODE_EXPORTER_PORT="9100"
PVE_EXPORTER_PORT="9221"
MONITORING_USER="pve-exporter"
API_TOKEN_NAME="exporter"

################################################################################
# Funktionen
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Dieses Script muss als root ausgeführt werden!"
        exit 1
    fi
}

get_hostname() {
    hostname -f
}

################################################################################
# node_exporter Installation
################################################################################

install_node_exporter() {
    log_info "Installiere node_exporter v${NODE_EXPORTER_VERSION}..."
    
    # Download
    cd /tmp
    wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    
    # Extrahieren
    tar xzf "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    
    # Binary installieren
    cp "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64/node_exporter" /usr/local/bin/
    chmod +x /usr/local/bin/node_exporter
    
    # Cleanup
    rm -rf "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64"*
    
    log_info "node_exporter Binary installiert"
}

create_node_exporter_user() {
    if ! id "node_exporter" &>/dev/null; then
        log_info "Erstelle node_exporter System-User..."
        useradd --no-create-home --shell /bin/false node_exporter
    else
        log_warn "User 'node_exporter' existiert bereits"
    fi
}

create_node_exporter_service() {
    log_info "Erstelle node_exporter systemd Service..."
    
    cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Prometheus Node Exporter
Documentation=https://github.com/prometheus/node_exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \\
    --web.listen-address=:${NODE_EXPORTER_PORT} \\
    --collector.filesystem.mount-points-exclude='^/(dev|proc|sys|var/lib/docker/.+|var/lib/kubelet/.+)($|/)' \\
    --collector.filesystem.fs-types-exclude='^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$'

SyslogIdentifier=node_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable node_exporter
    systemctl start node_exporter
    
    log_info "node_exporter Service gestartet"
}

################################################################################
# pve_exporter Installation
################################################################################

install_pve_exporter_dependencies() {
    log_info "Installiere Python3 und pip..."
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv
}

install_pve_exporter() {
    log_info "Installiere pve_exporter v${PVE_EXPORTER_VERSION}..."
    
    # Erstelle Virtual Environment
    python3 -m venv /opt/prometheus-pve-exporter
    
    # Installiere pve_exporter
    /opt/prometheus-pve-exporter/bin/pip install --quiet --upgrade pip
    /opt/prometheus-pve-exporter/bin/pip install --quiet prometheus-pve-exporter==${PVE_EXPORTER_VERSION}
    
    log_info "pve_exporter installiert"
}

create_pve_monitoring_user() {
    log_info "Erstelle Proxmox Monitoring User und API Token..."
    
    # Prüfe ob User existiert
    if pveum user list | grep -q "^${MONITORING_USER}@pve"; then
        log_warn "User '${MONITORING_USER}@pve' existiert bereits"
    else
        pveum user add ${MONITORING_USER}@pve --comment "Prometheus Monitoring User"
        log_info "User '${MONITORING_USER}@pve' erstellt"
    fi
    
    # Erstelle Monitoring-Rolle (falls nicht vorhanden)
    if ! pveum role list | grep -q "^PVEMonitoring"; then
        pveum role add PVEMonitoring -privs VM.Audit,Sys.Audit,Datastore.Audit,SDN.Audit
        log_info "Rolle 'PVEMonitoring' erstellt"
    else
        log_warn "Rolle 'PVEMonitoring' existiert bereits"
    fi
    
    # Weise Rolle zu
    pveum aclmod / -user ${MONITORING_USER}@pve -role PVEMonitoring
    log_info "Rolle 'PVEMonitoring' dem User zugewiesen"
    
    # Erstelle API Token (falls nicht vorhanden)
    if pveum user token list ${MONITORING_USER}@pve | grep -q "${API_TOKEN_NAME}"; then
        log_warn "API Token '${API_TOKEN_NAME}' existiert bereits"
        log_warn "Verwende existierenden Token - bitte Token-Value manuell in Config eintragen!"
        TOKEN_VALUE="EXISTING_TOKEN_PLEASE_CHECK"
    else
        # Token erstellen und Value extrahieren
        TOKEN_OUTPUT=$(pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0 --output-format=json)
        TOKEN_VALUE=$(echo $TOKEN_OUTPUT | grep -oP '(?<="value":")[^"]*')
        log_info "API Token erstellt: ${TOKEN_VALUE}"
    fi
    
    # Speichere Token für Config
    echo "$TOKEN_VALUE" > /tmp/pve_exporter_token.txt
}

create_pve_exporter_config() {
    log_info "Erstelle pve_exporter Konfiguration..."
    
    mkdir -p /etc/pve_exporter
    
    # Lese Token
    if [ -f /tmp/pve_exporter_token.txt ]; then
        TOKEN_VALUE=$(cat /tmp/pve_exporter_token.txt)
    else
        TOKEN_VALUE="BITTE_TOKEN_EINTRAGEN"
        log_warn "Token-Datei nicht gefunden - bitte Token manuell in Config eintragen!"
    fi
    
    cat > /etc/pve_exporter/config.yaml <<EOF
default:
  user: ${MONITORING_USER}@pve
  token_name: ${API_TOKEN_NAME}
  token_value: ${TOKEN_VALUE}
  verify_ssl: false
EOF
    
    chmod 600 /etc/pve_exporter/config.yaml
    chown root:root /etc/pve_exporter/config.yaml
    
    log_info "Config erstellt: /etc/pve_exporter/config.yaml"
    
    # Cleanup
    rm -f /tmp/pve_exporter_token.txt
}

create_pve_exporter_service() {
    log_info "Erstelle pve_exporter systemd Service..."
    
    cat > /etc/systemd/system/prometheus-pve-exporter.service <<EOF
[Unit]
Description=Prometheus Proxmox VE Exporter
Documentation=https://github.com/prometheus-pve/prometheus-pve-exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/prometheus-pve-exporter/bin/pve_exporter \\
    --config.file=/etc/pve_exporter/config.yaml \\
    --web.listen-address=0.0.0.0:${PVE_EXPORTER_PORT}

SyslogIdentifier=pve_exporter
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable prometheus-pve-exporter
    systemctl start prometheus-pve-exporter
    
    log_info "pve_exporter Service gestartet"
}

################################################################################
# Firewall-Konfiguration (optional)
################################################################################

configure_firewall() {
    log_info "Konfiguriere Firewall-Regeln..."
    
    # Prüfe ob pve-firewall aktiv ist
    if systemctl is-active --quiet pve-firewall; then
        log_warn "Proxmox Firewall aktiv - bitte Regeln manuell in Web-UI hinzufügen:"
        log_warn "  - Port ${NODE_EXPORTER_PORT}/tcp (node_exporter)"
        log_warn "  - Port ${PVE_EXPORTER_PORT}/tcp (pve_exporter)"
    else
        log_info "Proxmox Firewall nicht aktiv - keine Firewall-Konfiguration nötig"
    fi
}

################################################################################
# Verifikation
################################################################################

verify_installation() {
    log_info "Verifiziere Installation..."
    
    sleep 3  # Warte auf Service-Start
    
    # node_exporter
    if systemctl is-active --quiet node_exporter; then
        log_info "✓ node_exporter läuft"
        if curl -s http://localhost:${NODE_EXPORTER_PORT}/metrics | grep -q "node_exporter"; then
            log_info "✓ node_exporter liefert Metriken"
        else
            log_error "✗ node_exporter liefert keine Metriken"
        fi
    else
        log_error "✗ node_exporter läuft NICHT"
    fi
    
    # pve_exporter
    if systemctl is-active --quiet prometheus-pve-exporter; then
        log_info "✓ pve_exporter läuft"
        if curl -s http://localhost:${PVE_EXPORTER_PORT}/pve | grep -q "pve_"; then
            log_info "✓ pve_exporter liefert Metriken"
        else
            log_warn "✗ pve_exporter läuft, aber liefert keine Metriken (Permission-Problem?)"
        fi
    else
        log_error "✗ pve_exporter läuft NICHT"
    fi
}

print_summary() {
    echo ""
    echo "========================================================================"
    echo -e "${GREEN}Installation abgeschlossen!${NC}"
    echo "========================================================================"
    echo ""
    echo "Installierte Services:"
    echo "  • node_exporter:  http://$(get_hostname):${NODE_EXPORTER_PORT}/metrics"
    echo "  • pve_exporter:   http://$(get_hostname):${PVE_EXPORTER_PORT}/pve"
    echo ""
    echo "Konfiguration:"
    echo "  • node_exporter:  keine Config nötig"
    echo "  • pve_exporter:   /etc/pve_exporter/config.yaml"
    echo ""
    echo "Service-Verwaltung:"
    echo "  systemctl status node_exporter"
    echo "  systemctl status prometheus-pve-exporter"
    echo ""
    echo "Logs anzeigen:"
    echo "  journalctl -u node_exporter -f"
    echo "  journalctl -u prometheus-pve-exporter -f"
    echo ""
    echo "Prometheus Scrape-Konfiguration hinzufügen:"
    echo ""
    echo "  - job_name: 'proxmox-nodes'"
    echo "    static_configs:"
    echo "      - targets: ['$(get_hostname):${NODE_EXPORTER_PORT}']"
    echo "        labels:"
    echo "          instance: '$(get_hostname)'"
    echo ""
    echo "  - job_name: 'proxmox-cluster'"
    echo "    static_configs:"
    echo "      - targets: ['$(get_hostname):${PVE_EXPORTER_PORT}']"
    echo "        labels:"
    echo "          instance: '$(get_hostname)'"
    echo ""
    echo "========================================================================"
}

################################################################################
# Main
################################################################################

main() {
    echo "========================================================================"
    echo "Prometheus Exporters Installation für Proxmox VE"
    echo "Host: $(get_hostname)"
    echo "========================================================================"
    echo ""
    
    check_root
    
    # node_exporter
    log_info "=== node_exporter Installation ==="
    create_node_exporter_user
    install_node_exporter
    create_node_exporter_service
    echo ""
    
    # pve_exporter
    log_info "=== pve_exporter Installation ==="
    install_pve_exporter_dependencies
    install_pve_exporter
    create_pve_monitoring_user
    create_pve_exporter_config
    create_pve_exporter_service
    echo ""
    
    # Firewall
    configure_firewall
    echo ""
    
    # Verifikation
    verify_installation
    echo ""
    
    # Summary
    print_summary
}

# Script ausführen
main
