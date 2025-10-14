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
# Datum: 14.10.2025 - v1.2 (Idempotent & Safe)
################################################################################

# NICHT bei Fehler abbrechen (wir behandeln Fehler manuell)
set +e

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $1"
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
    # Prüfe ob node_exporter bereits läuft
    if systemctl is-active --quiet node_exporter; then
        log_skip "node_exporter läuft bereits - überspringe Installation"
        return 0
    fi
    
    # Prüfe ob Binary bereits existiert
    if [ -f "/usr/local/bin/node_exporter" ]; then
        log_warn "node_exporter Binary existiert bereits - verwende existierende"
        return 0
    fi
    
    log_info "Installiere node_exporter v${NODE_EXPORTER_VERSION}..."
    
    # Download
    cd /tmp
    wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    
    if [ $? -ne 0 ]; then
        log_error "Download fehlgeschlagen"
        return 1
    fi
    
    # Extrahieren
    tar xzf "node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz"
    
    # Stoppe Service falls er läuft (für Update)
    systemctl stop node_exporter 2>/dev/null || true
    
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
        log_skip "User 'node_exporter' existiert bereits"
    fi
}

create_node_exporter_service() {
    # Prüfe ob Service-Datei bereits existiert
    if [ -f "/etc/systemd/system/node_exporter.service" ] && systemctl is-active --quiet node_exporter; then
        log_skip "node_exporter Service läuft bereits"
        return 0
    fi
    
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
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-pip python3-venv 2>&1 | grep -v "^Extracting\|^Selecting\|^Preparing\|^Unpacking\|^Setting up\|^Processing"
}

install_pve_exporter() {
    # Prüfe ob bereits installiert
    if [ -f "/opt/prometheus-pve-exporter/bin/pve_exporter" ] && systemctl is-active --quiet prometheus-pve-exporter; then
        log_skip "pve_exporter läuft bereits - überspringe Installation"
        return 0
    fi
    
    log_info "Installiere pve_exporter v${PVE_EXPORTER_VERSION}..."
    
    # Erstelle Virtual Environment
    if [ ! -d "/opt/prometheus-pve-exporter" ]; then
        python3 -m venv /opt/prometheus-pve-exporter
    fi
    
    # Installiere pve_exporter
    /opt/prometheus-pve-exporter/bin/pip install --quiet --upgrade pip 2>/dev/null
    /opt/prometheus-pve-exporter/bin/pip install --quiet prometheus-pve-exporter==${PVE_EXPORTER_VERSION} 2>/dev/null
    
    log_info "pve_exporter installiert"
}

create_pve_monitoring_user() {
    log_info "Konfiguriere Proxmox Monitoring User und Permissions..."
    
    # Prüfe ob User existiert
    if pveum user list | grep -q "^${MONITORING_USER}@pve"; then
        log_skip "User '${MONITORING_USER}@pve' existiert bereits"
    else
        pveum user add ${MONITORING_USER}@pve --comment "Prometheus Monitoring User" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_info "User '${MONITORING_USER}@pve' erstellt"
        else
            log_warn "User konnte nicht erstellt werden (existiert vermutlich bereits)"
        fi
    fi
    
    # Erstelle Monitoring-Rolle (falls nicht vorhanden)
    if ! pveum role list | grep -q "^PVEMonitoring"; then
        pveum role add PVEMonitoring -privs VM.Audit,Sys.Audit,Datastore.Audit,SDN.Audit 2>/dev/null
        log_info "Rolle 'PVEMonitoring' erstellt"
    else
        log_skip "Rolle 'PVEMonitoring' existiert bereits"
    fi
    
    # Weise Rolle zu (immer ausführen)
    pveum aclmod / -user ${MONITORING_USER}@pve -role PVEMonitoring 2>/dev/null
    log_info "Rolle 'PVEMonitoring' zugewiesen"
}

create_or_get_api_token() {
    log_info "Prüfe API Token..."
    
    # Prüfe ob Token existiert
    if pveum user token list ${MONITORING_USER}@pve 2>/dev/null | grep -q "${API_TOKEN_NAME}"; then
        log_warn "API Token '${API_TOKEN_NAME}' existiert bereits"
        
        # Versuche Token aus existierender Config zu lesen
        if [ -f "/etc/pve_exporter/config.yaml" ]; then
            EXISTING_TOKEN=$(grep "token_value:" /etc/pve_exporter/config.yaml | awk '{print $2}')
            if [ ! -z "$EXISTING_TOKEN" ] && [ "$EXISTING_TOKEN" != "EXISTING_TOKEN_BITTE_MANUELL_EINTRAGEN" ]; then
                log_info "Verwende Token aus existierender Config"
                echo "$EXISTING_TOKEN" > /tmp/pve_exporter_token.txt
                return 0
            fi
        fi
        
        log_warn ""
        log_warn "Token existiert, aber Value unbekannt. Optionen:"
        log_warn "1. Existierenden Token löschen und neu erstellen:"
        log_warn "   pveum user token remove ${MONITORING_USER}@pve ${API_TOKEN_NAME}"
        log_warn "   pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0"
        log_warn ""
        log_warn "2. Token manuell in Config eintragen:"
        log_warn "   nano /etc/pve_exporter/config.yaml"
        log_warn ""
        
        echo "EXISTING_TOKEN_BITTE_MANUELL_EINTRAGEN" > /tmp/pve_exporter_token.txt
        return 0
    fi
    
    # Token erstellen
    log_info "Erstelle neuen API Token..."
    TOKEN_OUTPUT=$(pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0 2>&1)
    
    # Extrahiere Token Value
    TOKEN_VALUE=$(echo "$TOKEN_OUTPUT" | grep -oP "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})" | head -1)
    
    if [ -z "$TOKEN_VALUE" ]; then
        log_error "Konnte Token nicht extrahieren!"
        echo "TOKEN_EXTRACTION_FAILED" > /tmp/pve_exporter_token.txt
        return 1
    fi
    
    log_info "API Token erstellt: ${TOKEN_VALUE}"
    echo "$TOKEN_VALUE" > /tmp/pve_exporter_token.txt
}

create_pve_exporter_config() {
    log_info "Erstelle pve_exporter Konfiguration..."
    
    mkdir -p /etc/pve_exporter
    
    # Lese Token
    if [ -f /tmp/pve_exporter_token.txt ]; then
        TOKEN_VALUE=$(cat /tmp/pve_exporter_token.txt)
    else
        TOKEN_VALUE="TOKEN_NOT_FOUND_BITTE_MANUELL_EINTRAGEN"
        log_warn "Token-Datei nicht gefunden"
    fi
    
    # Erstelle Config nur wenn sie nicht existiert oder Token fehlt
    if [ ! -f "/etc/pve_exporter/config.yaml" ] || grep -q "BITTE_MANUELL_EINTRAGEN\|NOT_FOUND\|EXTRACTION_FAILED" /etc/pve_exporter/config.yaml 2>/dev/null; then
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
    else
        log_skip "Config existiert bereits: /etc/pve_exporter/config.yaml"
    fi
    
    # Cleanup
    rm -f /tmp/pve_exporter_token.txt
}

create_pve_exporter_service() {
    # Prüfe ob Service läuft
    if [ -f "/etc/systemd/system/prometheus-pve-exporter.service" ] && systemctl is-active --quiet prometheus-pve-exporter; then
        log_skip "pve_exporter Service läuft bereits"
        return 0
    fi
    
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
    systemctl enable prometheus-pve-exporter 2>/dev/null
    systemctl restart prometheus-pve-exporter
    
    log_info "pve_exporter Service gestartet"
}

################################################################################
# Verifikation
################################################################################

verify_installation() {
    log_info "Verifiziere Installation..."
    
    sleep 3
    
    echo ""
    
    # node_exporter
    if systemctl is-active --quiet node_exporter; then
        if curl -s http://localhost:${NODE_EXPORTER_PORT}/metrics | grep -q "node_exporter"; then
            log_info "✓ node_exporter läuft und liefert Metriken"
        else
            log_warn "✗ node_exporter läuft, aber keine Metriken"
        fi
    else
        log_error "✗ node_exporter läuft NICHT"
    fi
    
    # pve_exporter
    if systemctl is-active --quiet prometheus-pve-exporter; then
        if curl -s http://localhost:${PVE_EXPORTER_PORT}/pve 2>/dev/null | grep -q "pve_"; then
            log_info "✓ pve_exporter läuft und liefert Metriken"
        else
            log_warn "✗ pve_exporter läuft, aber keine Metriken"
            log_warn "  Prüfe Token in: /etc/pve_exporter/config.yaml"
            log_warn "  Logs: journalctl -u prometheus-pve-exporter -n 20"
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
    
    # Prüfe ob Token manuell eingetragen werden muss
    if [ -f "/etc/pve_exporter/config.yaml" ] && grep -q "BITTE_MANUELL_EINTRAGEN\|NOT_FOUND\|EXTRACTION_FAILED" /etc/pve_exporter/config.yaml 2>/dev/null; then
        echo -e "${YELLOW}⚠ ACHTUNG: Token muss manuell eingetragen werden!${NC}"
        echo ""
        echo "Schritte:"
        echo "1. Lösche alten Token und erstelle neuen:"
        echo "   pveum user token remove ${MONITORING_USER}@pve ${API_TOKEN_NAME}"
        echo "   pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0"
        echo ""
        echo "2. Kopiere den angezeigten Token-Value"
        echo ""
        echo "3. Trage ihn in die Config ein:"
        echo "   nano /etc/pve_exporter/config.yaml"
        echo ""
        echo "4. Service neu starten:"
        echo "   systemctl restart prometheus-pve-exporter"
        echo ""
    fi
    
    echo "Service-Status:"
    echo "  systemctl status node_exporter"
    echo "  systemctl status prometheus-pve-exporter"
    echo ""
    echo "Logs:"
    echo "  journalctl -u node_exporter -f"
    echo "  journalctl -u prometheus-pve-exporter -f"
    echo ""
    echo "Prometheus Scrape-Config:"
    echo ""
    echo "  - job_name: 'proxmox-nodes'"
    echo "    static_configs:"
    echo "      - targets: ['$(get_hostname):${NODE_EXPORTER_PORT}']"
    echo ""
    echo "  - job_name: 'proxmox-cluster'"
    echo "    static_configs:"
    echo "      - targets: ['$(get_hostname):${PVE_EXPORTER_PORT}']"
    echo ""
    echo "========================================================================"
}

################################################################################
# Main
################################################################################

main() {
    echo "========================================================================"
    echo "Prometheus Exporters Installation für Proxmox VE v1.2"
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
    create_or_get_api_token
    create_pve_exporter_config
    create_pve_exporter_service
    echo ""
    
    # Verifikation
    verify_installation
    echo ""
    
    # Summary
    print_summary
}

# Script ausführen
main