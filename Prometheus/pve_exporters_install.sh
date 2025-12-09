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
AUTH_METHOD=""  # Wird später gesetzt: "token" oder "password"

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

check_proxmox_environment() {
    log_info "Prüfe Proxmox VE Umgebung..."

    # Prüfe ob pveum vorhanden ist
    if ! command -v pveum &> /dev/null; then
        log_error "pveum command nicht gefunden!"
        log_error "Dieses Script muss auf einem Proxmox VE Host ausgeführt werden."
        log_error "Bitte führen Sie das Script direkt auf dem PVE-Host aus:"
        log_error "  ssh root@ihr-pve-host.domain"
        log_error "  bash -c \"\$(curl -s https://raw.githubusercontent.com/...)\""
        exit 1
    fi

    # Prüfe ob PVE installiert ist
    if [ ! -f /etc/pve/datacenter.cfg ]; then
        log_error "Proxmox VE Konfiguration nicht gefunden!"
        log_error "Ist Proxmox VE korrekt installiert?"
        exit 1
    fi

    log_info "✓ Proxmox VE Umgebung erkannt"
}

get_hostname() {
    hostname -f
}

ask_auth_method() {
    echo ""
    echo "========================================================================"
    echo "Authentifizierungsmethode für pve_exporter auswählen"
    echo "========================================================================"
    echo ""
    echo "Es gibt zwei Möglichkeiten zur Authentifizierung:"
    echo ""
    echo "1) API Token (empfohlen, sicherer)"
    echo "   + Keine Passwörter in Konfigurationsdateien"
    echo "   + Kann bei Bedarf widerrufen werden"
    echo "   - Erfordert manuelle Token-Eingabe nach Installation"
    echo ""
    echo "2) Passwort (einfacher, weniger sicher)"
    echo "   + Funktioniert sofort nach Installation"
    echo "   + Keine manuelle Nachbearbeitung nötig"
    echo "   - Passwort wird in Klartext gespeichert (/etc/pve_exporter/config.yaml)"
    echo "   - Nur für nicht-kritische Umgebungen empfohlen"
    echo ""
    echo "========================================================================"
    echo ""

    while true; do
        read -p "Welche Methode möchten Sie verwenden? (1/2): " choice
        case $choice in
            1)
                AUTH_METHOD="token"
                log_info "✓ API Token-Authentifizierung gewählt"
                break
                ;;
            2)
                AUTH_METHOD="password"
                log_info "✓ Passwort-Authentifizierung gewählt"
                break
                ;;
            *)
                log_error "Ungültige Eingabe. Bitte 1 oder 2 wählen."
                ;;
        esac
    done
    echo ""
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
    log_info "Konfiguriere Proxmox Monitoring User und Permissions..."

    # Erstelle User (mit Fehlerbehandlung - deaktiviere set -e temporär)
    if pveum user list | grep -q "^${MONITORING_USER}@pve"; then
        log_warn "User '${MONITORING_USER}@pve' existiert bereits"
    else
        set +e  # Deaktiviere exit on error
        pveum user add ${MONITORING_USER}@pve --comment "Prometheus Monitoring User" 2>/dev/null
        USER_CREATE_RESULT=$?
        set -e  # Reaktiviere exit on error

        if [ $USER_CREATE_RESULT -eq 0 ]; then
            log_info "User '${MONITORING_USER}@pve' erstellt"
        else
            log_warn "User konnte nicht erstellt werden (existiert möglicherweise bereits)"
        fi
    fi

    # Erstelle Monitoring-Rolle (falls nicht vorhanden)
    if pveum role list | grep -q "^PrometheusMonitoring"; then
        log_warn "Rolle 'PrometheusMonitoring' existiert bereits"
    else
        set +e  # Deaktiviere exit on error
        pveum role add PrometheusMonitoring -privs VM.Audit,Sys.Audit,Datastore.Audit,SDN.Audit 2>/dev/null
        ROLE_CREATE_RESULT=$?
        set -e  # Reaktiviere exit on error

        if [ $ROLE_CREATE_RESULT -eq 0 ]; then
            log_info "Rolle 'PrometheusMonitoring' erstellt"
        else
            log_warn "Rolle konnte nicht erstellt werden (existiert möglicherweise bereits)"
        fi
    fi

    # Weise Rolle zu (mit Fehlerbehandlung für bereits zugewiesene Rollen)
    set +e  # Deaktiviere exit on error
    pveum aclmod / -user ${MONITORING_USER}@pve -role PrometheusMonitoring 2>/dev/null
    ACL_RESULT=$?
    set -e  # Reaktiviere exit on error

    if [ $ACL_RESULT -eq 0 ]; then
        log_info "Rolle 'PrometheusMonitoring' dem User zugewiesen"
    else
        log_warn "Rolle war bereits zugewiesen"
    fi
}

setup_token_auth() {
    log_info "Prüfe API Token..."

    # Erstelle API Token (falls nicht vorhanden)
    if pveum user token list ${MONITORING_USER}@pve 2>/dev/null | grep -q "${API_TOKEN_NAME}"; then
        log_warn "API Token '${API_TOKEN_NAME}' existiert bereits"
        log_warn "Falls der Token nicht funktioniert, löschen Sie ihn mit:"
        log_warn "  pveum user token remove ${MONITORING_USER}@pve ${API_TOKEN_NAME}"
        log_warn "und führen Sie das Script erneut aus."
        TOKEN_VALUE="EXISTING_TOKEN_BITTE_MANUELL_EINTRAGEN"
    else
        log_info "Erstelle neuen API Token..."
        # Token erstellen - Output-Format für bessere Extraktion
        TOKEN_OUTPUT=$(pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0 2>&1)

        # Versuche Token aus verschiedenen Output-Formaten zu extrahieren
        TOKEN_VALUE=$(echo "$TOKEN_OUTPUT" | grep -oP '(?<=value:\s)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)

        if [ -z "$TOKEN_VALUE" ]; then
            # Alternative: Versuche JSON-Format
            TOKEN_VALUE=$(echo "$TOKEN_OUTPUT" | grep -oP '(?<="value":")[^"]*')
        fi

        if [ -n "$TOKEN_VALUE" ] && [ "$TOKEN_VALUE" != "null" ]; then
            log_info "API Token erfolgreich erstellt!"
            echo ""
            echo "========================================================================"
            echo -e "${GREEN}WICHTIG: API Token (bitte kopieren):${NC}"
            echo "$TOKEN_VALUE"
            echo "========================================================================"
            echo ""
        else
            log_error "Konnte Token nicht extrahieren!"
            log_warn "Bitte Token manuell erstellen mit:"
            log_warn "  pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0"
            TOKEN_VALUE="BITTE_TOKEN_HIER_EINTRAGEN"
        fi
    fi

    # Speichere Token für Config
    echo "$TOKEN_VALUE" > /tmp/pve_exporter_token.txt
}

setup_password_auth() {
    log_info "Richte Passwort-Authentifizierung ein..."

    # Generiere sicheres Passwort
    USER_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-20)

    # Setze Passwort für User (verwende pveum passwd)
    echo -e "${USER_PASSWORD}\n${USER_PASSWORD}" | pveum passwd ${MONITORING_USER}@pve

    log_info "Passwort für User '${MONITORING_USER}@pve' gesetzt"

    # Speichere Passwort für Config
    echo "$USER_PASSWORD" > /tmp/pve_exporter_password.txt

    echo ""
    echo "========================================================================"
    echo -e "${GREEN}Generiertes Passwort für ${MONITORING_USER}@pve:${NC}"
    echo "$USER_PASSWORD"
    echo ""
    echo "Das Passwort wird automatisch in die Config eingetragen."
    echo "========================================================================"
    echo ""
}

create_pve_exporter_config() {
    log_info "Erstelle pve_exporter Konfiguration..."

    mkdir -p /etc/pve_exporter

    if [ "$AUTH_METHOD" = "token" ]; then
        # Token-basierte Konfiguration
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

        # Cleanup
        rm -f /tmp/pve_exporter_token.txt

    else
        # Passwort-basierte Konfiguration
        if [ -f /tmp/pve_exporter_password.txt ]; then
            USER_PASSWORD=$(cat /tmp/pve_exporter_password.txt)
        else
            USER_PASSWORD="BITTE_PASSWORT_EINTRAGEN"
            log_warn "Passwort-Datei nicht gefunden - bitte Passwort manuell in Config eintragen!"
        fi

        cat > /etc/pve_exporter/config.yaml <<EOF
default:
  user: ${MONITORING_USER}@pve
  password: ${USER_PASSWORD}
  verify_ssl: false
EOF

        # Cleanup
        rm -f /tmp/pve_exporter_password.txt
    fi

    chmod 600 /etc/pve_exporter/config.yaml
    chown root:root /etc/pve_exporter/config.yaml

    log_info "Config erstellt: /etc/pve_exporter/config.yaml"
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
            log_warn "✗ pve_exporter läuft, aber keine Metriken"
            if [ "$AUTH_METHOD" = "token" ]; then
                log_warn "  Prüfe Token in: /etc/pve_exporter/config.yaml"
            else
                log_warn "  Prüfe Logs: journalctl -u prometheus-pve-exporter -n 20"
            fi
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

    if [ "$AUTH_METHOD" = "token" ]; then
        echo ""
        echo "Authentifizierung: API Token"
        echo ""
        echo -e "${YELLOW}⚠ WICHTIG:${NC} Wenn der Token nicht automatisch eingetragen wurde:"
        echo "  1. Erstellen Sie einen neuen Token:"
        echo "     pveum user token add ${MONITORING_USER}@pve ${API_TOKEN_NAME} --privsep 0"
        echo ""
        echo "  2. Kopieren Sie den angezeigten Token-Value"
        echo ""
        echo "  3. Tragen Sie ihn in die Config ein:"
        echo "     nano /etc/pve_exporter/config.yaml"
        echo ""
        echo "  4. Service neu starten:"
        echo "     systemctl restart prometheus-pve-exporter"
    else
        echo ""
        echo "Authentifizierung: Passwort (automatisch konfiguriert)"
        echo -e "${GREEN}✓${NC} pve_exporter ist sofort einsatzbereit!"
        echo ""
        echo -e "${YELLOW}Sicherheitshinweis:${NC}"
        echo "  Das Passwort ist in /etc/pve_exporter/config.yaml gespeichert."
        echo "  Für produktive Umgebungen wird API Token-Authentifizierung empfohlen."
    fi

    echo ""
    echo "Service-Status prüfen:"
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
    echo "Prometheus Exporters Installation für Proxmox VE v1.3"
    echo "Host: $(get_hostname)"
    echo "========================================================================"
    echo ""

    check_root
    check_proxmox_environment

    # Authentifizierungsmethode wählen
    ask_auth_method

    # node_exporter
    log_info "=== node_exporter Installation ==="
    create_node_exporter_user

    # Prüfe ob node_exporter bereits läuft
    if systemctl is-active --quiet node_exporter; then
        log_warn "node_exporter läuft bereits - überspringe Installation"
    else
        install_node_exporter
        create_node_exporter_service
    fi
    echo ""

    # pve_exporter
    log_info "=== pve_exporter Installation ==="
    install_pve_exporter_dependencies

    # Prüfe ob pve_exporter bereits läuft
    if systemctl is-active --quiet prometheus-pve-exporter; then
        log_warn "pve_exporter läuft bereits - überspringe Installation"
        log_warn "Um die Authentifizierung zu ändern, stoppen Sie den Service:"
        log_warn "  systemctl stop prometheus-pve-exporter"
    else
        install_pve_exporter
    fi

    create_pve_monitoring_user

    # Authentifizierung einrichten (basierend auf Auswahl)
    if [ "$AUTH_METHOD" = "token" ]; then
        setup_token_auth
    else
        setup_password_auth
    fi

    create_pve_exporter_config

    # Service nur starten wenn noch nicht aktiv
    if ! systemctl is-active --quiet prometheus-pve-exporter; then
        create_pve_exporter_service
    else
        log_info "Starte pve_exporter Service neu mit neuer Konfiguration..."
        systemctl restart prometheus-pve-exporter
    fi
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
