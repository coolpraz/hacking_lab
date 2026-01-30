#!/bin/bash

# Hacking Lab Management Script
# Usage: ./lab.sh [command] [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║     ETHICAL HACKING LAB MANAGEMENT SCRIPT         ║"
    echo "║     For Educational Purposes Only                 ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
}

start_lab() {
    print_status "Starting Hacking Lab..."
    print_warning "Make sure you have at least 8GB RAM available!"
    docker compose up -d
    print_status "Lab started successfully!"
    print_status "Run './lab.sh status' to see running services"
    print_status "Run './lab.sh urls' to see all available URLs"
}

stop_lab() {
    print_status "Stopping Hacking Lab..."
    docker compose down
    print_status "Lab stopped successfully!"
}

stop_lab_clean() {
    print_warning "This will remove all containers, volumes, and data!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        print_status "Stopping and cleaning Hacking Lab..."
        docker compose down -v
        docker system prune -f
        print_status "Lab cleaned successfully!"
    else
        print_status "Cleanup cancelled."
    fi
}

show_status() {
    print_status "Container Status:"
    echo ""
    docker compose ps
    echo ""
    print_status "Resource Usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" $(docker compose ps -q)
}

show_logs() {
    if [ -z "$1" ]; then
        print_error "Please specify a service name."
        echo "Usage: ./lab.sh logs [service_name]"
        echo "Example: ./lab.sh logs dvwa"
        exit 1
    fi
    print_status "Showing logs for $1 (Ctrl+C to exit)..."
    docker compose logs -f "$1"
}

show_urls() {
    print_status "Available Services:"
    echo ""
    echo -e "${GREEN}=== Core Web Applications ===${NC}"
    echo "DVWA:                http://localhost:8080"
    echo "WebGoat:             http://localhost:8081/webgoat"
    echo "WebWolf:             http://localhost:9090"
    echo "bWAPP:               http://localhost:8082"
    echo "Juice Shop:          http://localhost:3000"
    echo ""
    echo -e "${GREEN}=== CMS ===${NC}"
    echo "WordPress:           http://localhost:8084"
    echo ""
    echo -e "${GREEN}=== DevOps Tools ===${NC}"
    echo "Jenkins:             http://localhost:8087"
    echo ""
    echo -e "${GREEN}=== Specialized Vulnerable Apps ===${NC}"
    echo "SQLi-Labs:           http://localhost:8091"
    echo "Damn Vuln GraphQL:   http://localhost:8092"
    echo "Damn Vuln Restaurant:http://localhost:8093"
    echo "Pixi (XSS):          http://localhost:8094"
    echo "PyGoat:              http://localhost:8095"
    echo "SSRF Lab:            http://localhost:8096"
    echo "OWASP WrongSecrets:  http://localhost:8099"
    echo "Hackazon:            http://localhost:8104"
    echo "VulnShop:            http://localhost:8106"
    echo ""
    echo -e "${GREEN}=== Network Services ===${NC}"
    echo "FTP (VSFTPD):        localhost:21"
    echo "Telnet:              localhost:2323"
    echo "Samba:               localhost:139, 445"
    echo ""
    echo -e "${GREEN}=== Databases ===${NC}"
    echo "MySQL:               localhost:3306"
    echo "PostgreSQL:          localhost:5432"
    echo "MongoDB:             localhost:27017"
    echo "Redis:               localhost:6379"
}

restart_service() {
    if [ -z "$1" ]; then
        print_error "Please specify a service name."
        echo "Usage: ./lab.sh restart [service_name]"
        echo "Example: ./lab.sh restart dvwa"
        exit 1
    fi
    print_status "Restarting $1..."
    docker compose restart "$1"
    print_status "$1 restarted successfully!"
}

shell_into() {
    if [ -z "$1" ]; then
        print_error "Please specify a service name."
        echo "Usage: ./lab.sh shell [service_name]"
        echo "Example: ./lab.sh shell dvwa"
        exit 1
    fi
    print_status "Opening shell into $1..."
    docker compose exec "$1" /bin/bash || docker compose exec "$1" /bin/sh
}

rebuild_lab() {
    print_status "Rebuilding Hacking Lab..."
    docker compose down
    docker compose build
    docker compose up -d
    print_status "Lab rebuilt successfully!"
}

show_credentials() {
    print_status "Common Default Credentials:"
    echo ""
    echo -e "${GREEN}=== Web Applications ===${NC}"
    echo "DVWA:                admin:password, admin:admin"
    echo "bWAPP:               bee:bug"
    echo ""
    echo -e "${GREEN}=== CMS ===${NC}"
    echo "WordPress:           admin:admin, wpuser:wppassword"
    echo "Joomla:              admin:admin"
    echo ""
    echo -e "${GREEN}=== DevOps Tools ===${NC}"
    echo "Jenkins:             admin:admin"
    echo "Grafana:             admin:admin"
    echo ""
    echo -e "${GREEN}=== Databases ===${NC}"
    echo "MySQL:               root:root, testuser:password123"
    echo "PostgreSQL:          postgres:postgres"
    echo "MongoDB:             No authentication"
    echo "Redis:               No authentication"
}

network_scan() {
    print_warning "Scanning Docker network for running services..."
    docker network inspect hacking_lab_hacking_lab | grep -A 10 "Containers"
}

check_requirements() {
    print_status "Checking system requirements..."
    check_docker

    # Check memory
    if [[ "$OSTYPE" == "darwin"* ]]; then
        MEMORY=$(system_profiler SPHardwareDataType | grep "Memory:" | awk '{print $2 $3}')
    else
        MEMORY=$(free -h | awk '/^Mem:/ {print $2}')
    fi
    print_status "Available Memory: $MEMORY"

    # Check disk space
    DISK=$(df -h . | tail -1 | awk '{print $4}')
    print_status "Available Disk: $DISK"

    print_status "System check complete!"
    print_warning "Make sure Docker has at least 4GB memory allocated"
}

show_help() {
    echo "Usage: ./lab.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  start              Start the hacking lab"
    echo "  stop               Stop the hacking lab"
    echo "  clean              Stop and remove all containers and volumes"
    echo "  status             Show status of running containers"
    echo "  logs [service]     Show logs for a specific service"
    echo "  urls               Show all available service URLs"
    echo "  restart [service]  Restart a specific service"
    echo "  shell [service]    Open shell into a service container"
    echo "  rebuild            Rebuild and restart the lab"
    echo "  credentials        Show common default credentials"
    echo "  network            Show network information"
    echo "  check              Check system requirements"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./lab.sh start"
    echo "  ./lab.sh logs dvwa"
    echo "  ./lab.sh shell dvwa"
    echo "  ./lab.sh restart mysql_weak"
}

# Main script logic
case "$1" in
    start)
        print_banner
        check_docker
        start_lab
        ;;
    stop)
        print_banner
        stop_lab
        ;;
    clean)
        print_banner
        stop_lab_clean
        ;;
    status)
        print_banner
        show_status
        ;;
    logs)
        print_banner
        show_logs "$2"
        ;;
    urls)
        print_banner
        show_urls
        ;;
    restart)
        print_banner
        restart_service "$2"
        ;;
    shell)
        print_banner
        shell_into "$2"
        ;;
    rebuild)
        print_banner
        rebuild_lab
        ;;
    credentials)
        print_banner
        show_credentials
        ;;
    network)
        print_banner
        network_scan
        ;;
    check)
        print_banner
        check_requirements
        ;;
    help|--help|-h)
        print_banner
        show_help
        ;;
    *)
        print_banner
        show_help
        exit 1
        ;;
esac

exit 0
