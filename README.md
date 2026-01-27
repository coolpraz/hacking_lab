# Hacking Lab - Ethical Hacking Practice Environment

A comprehensive Docker-based lab environment for practicing ethical hacking, penetration testing, and offensive security techniques. This lab contains multiple vulnerable machines and services commonly found in CTF challenges, security certifications (OSCP, CEH, eJPT), and real-world scenarios.

## WARNING - IMPORTANT NOTICE

**This lab is for EDUCATIONAL PURPOSES ONLY.**
- Use only on isolated networks
- Do NOT expose to the internet
- Practice ethical hacking only
- You are responsible for ensuring proper authorization before testing similar techniques in production

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Vulnerable Services](#vulnerable-services)
- [Lab Network](#lab-network)
- [Usage Examples](#usage-examples)
- [Common Credentials](#common-credentials)
- [Practice Areas](#practice-areas)
- [Stopping the Lab](#stopping-the-lab)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 8GB RAM
- 20GB free disk space

## Quick Start

```bash
# Clone or navigate to the directory
cd hacking_lab

# Start all vulnerable services
docker-compose up -d

# Check running containers
docker-compose ps

# View logs for a specific service
docker-compose logs -f dvwa
```

## Vulnerable Services

### Web Application Vulnerabilities

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **DVWA** | 8080 | Damn Vulnerable Web Application | SQLi, XSS, CSRF, File Upload, Authentication Bypass |
| **WebGoat** | 8081 | OWASP Java-based lessons | Injection, XSS, CSRF, Auth flaws, Advanced attacks |
| **bWAPP** | 8082 | Buggy Web Application | 100+ vulnerabilities, all OWASP Top 10 |
| **Mutillidae** | 8083 | OWASP-focused targets | Server-side & Client-side attacks |
| **Juice Shop** | 3000 | Modern OWASP Top 10 | DOM XSS, JWT flaws, Server-side XSS |

### Content Management Systems

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **WordPress** | 8084 | WordPress 5.9 (older version) | Plugin vulns, theme exploits, known CVEs |
| **Joomla** | 8085 | Joomla 3.10 | Extension vulnerabilities, RCE |

### Network Services

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **VSFTPD** | 21 | FTP 2.3.4 | Backdoor vulnerability (CVE-2011-2523) |
| **ProFTPD** | 2121 | ProFTPD | Authentication bypass, directory traversal |
| **Pure-FTPd** | 2221 | Pure-FTPd | Arbitrary file download, auth issues |
| **Telnet** | 2323 | Telnet Server | Cleartext credentials, brute force |
| **SSH** | 2222 | SSH Weak Config | Weak keys, outdated algorithms |
| **Samba** | 139/445 | SMB/CIFS | Anonymous login, symlink traversal, RCE |

### Databases

| Service | Port | Description | Credentials |
|---------|------|-------------|-------------|
| **MySQL** | 3306 | MySQL 5.7 | root:root, testuser:password123 |
| **PostgreSQL** | 5432 | PostgreSQL 13 | postgres:postgres |
| **MongoDB** | 27017 | MongoDB 4.4 | No authentication |

### Application Servers & DevOps Tools

| Service | Port | Description | Credentials |
|---------|------|-------------|-------------|
| **Tomcat** | 8086 | Apache Tomcat 8.5 | Default manager access |
| **Jenkins** | 8087 | Jenkins CI/CD | admin:admin |
| **Redis** | 6379 | Redis 6.2 | No authentication |
| **ElasticSearch** | 9200/9300 | ElasticSearch 7.10 | No authentication |
| **Grafana** | 3001 | Grafana 7.5.0 | admin:admin |
| **Struts2** | 8088 | Apache Struts | RCE (CVE-2017-5638) |

### Email Services

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **SMTP** | 25/587 | SMTP Server | Relay attacks, spoofing |

### Additional OWASP Vulnerable Applications

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **OWASP VulnerableApp** | 8090 | Comprehensive vulnerable app | All OWASP Top 10, real-world scenarios |
| **SQLi-Labs** | 8091 | SQL Injection practice | 25+ SQLi scenarios, different databases |
| **Damn Vulnerable GraphQL** | 8092 | GraphQL security | GraphQL injection, IDOR, bypasses |
| **Damn Vulnerable RESTaurant** | 8093 | REST API vulnerabilities | API security flaws, broken authentication |
| **Pixi** | 8094 | XSS practice | Reflected, stored, DOM XSS |
| **PyGoat** | 8095 | Python web vulnerabilities | Python-specific flaws, Flask vulns |
| **SSRF Lab** | 8096 | Server-Side Request Forgery | SSRF in various contexts |
| **VulnBank** | 8097 | Banking application | Business logic flaws, IDOR |
| **VulnLab** | 8098 | Multiple vulnerabilities | Various web app vulnerabilities |
| **OWASP WrongSecrets** | 8099 | Secrets management | Hardcoded secrets, leaked credentials |
| **Yrprey** | 8100 | Phishing platform | Social engineering, email spoofing |
| **Zero Health** | 8101 | Healthcare app | Medical data exposure, auth bypass |

### API & Web Service Vulnerabilities

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|-----------------|
| **VulnAPI** | 8102 | REST API testing | API key exposure, rate limiting |
| **DVWS** | 8103 | Vulnerable Web Services | SOAP/XML vulnerabilities |
| **Hackazon** | 8104 | E-commerce platform | Shopping cart logic, payment flaws |
| **Padding Oracle** | 8105 | Crypto attacks | Padding oracle vulnerabilities |
| **VulnShop** | 8106 | Business logic flaws | Price manipulation, coupon abuse |

## Lab Network

All services run on an isolated Docker network: `10.10.10.0/24`

### Accessing Services

```bash
# From host machine
curl http://localhost:8080  # DVWA
ssh root@localhost -p 2222  # SSH service
telnet localhost 2323       # Telnet service
```

### Internal Network Access

```bash
# Access from one container to another
docker-compose exec dvwa ping mysql_weak

# Shell into a container
docker-compose exec dvwa /bin/bash
```

## Usage Examples

### Web Application Penetration Testing

```bash
# Start DVWA and access at http://localhost:8080
# Default credentials: admin:password or admin:admin

# Start scanning with Nikto
nikto -h http://localhost:8080

# Use SQLMap for SQL injection testing
sqlmap -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session"

# Directory brute-forcing
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt
```

### Network Service Testing

```bash
# FTP version detection
nmap -sV -p 21 localhost

# VSFTPD backdoor check
telnet localhost 21
# User: smile:)
# Pass: smile

# SMB enumeration
nmap -p 139,445 --script smb-vuln-ms17-010 localhost

# SSH brute force with Hydra
hydra -L users.txt -P passwords.txt ssh://localhost:2222
```

### Database Exploitation

```bash
# MySQL connection
mysql -h localhost -P 3306 -u root -p

# MongoDB connection
mongo --host localhost --port 27017

# PostgreSQL connection
psql -h localhost -p 5432 -U postgres -d testdb
```

### CMS Exploitation

```bash
# WordPress version detection
curl -I http://localhost:8084

# WPScan for WordPress vulnerabilities
wpscan --url http://localhost:8084 --enumerate u

# Joomla enumeration
curl http://localhost:8085/administrator/
```

## Common Default Credentials

### Web Applications
- **DVWA**: admin:password, admin:admin, user:password
- **bWAPP**: bee:bug
- **Mutillidae**: No auth required (default)

### CMS
- **WordPress**: admin:admin, wpuser:wppassword
- **Joomla**: admin:admin

### DevOps Tools
- **Jenkins**: admin:admin
- **Grafana**: admin:admin

### Databases
- **MySQL**: root:root, testuser:password123
- **PostgreSQL**: postgres:postgres
- **MongoDB**: No authentication

### Network Services
- **SSH**: root:password123, admin:admin123
- **FTP**: anonymous:anonymous, ftp:ftp
- **Samba**: guest:guest

## Practice Areas

### 1. OWASP Top 10
- Injection attacks (SQLi, Command Injection, LDAP)
- Broken Authentication
- XSS (Reflected, Stored, DOM-based)
- CSRF (Cross-Site Request Forgery)
- Security Misconfiguration
- File Upload Vulnerabilities
- Insecure Deserialization

### 2. Network Penetration Testing
- Service enumeration
- Vulnerability scanning
- Brute force attacks
- Exploitation (VSFTPD backdoor, Samba RCE)
- Privilege escalation

### 3. Web Application Penetration Testing
- Manual testing techniques
- Automated scanning (Nikto, OWASP ZAP)
- SQL injection exploitation
- XSS payload testing
- File upload bypass techniques
- Authentication bypass

### 4. Database Security
- SQL injection
- NoSQL injection
- Authentication bypass
- Data extraction
- Privilege escalation

### 5. CMS Exploitation
- Plugin/Theme vulnerabilities
- Version-specific exploits
- Admin panel access
- Webshell upload
- Remote code execution

### 6. DevOps & Cloud Security
- CI/CD pipeline vulnerabilities
- Exposed management interfaces
- Default credential exploitation
- Container escape techniques

### 7. Authentication & Authorization
- Password cracking (John the Ripper, Hashcat)
- Session hijacking
- JWT manipulation
- Token exploitation

## Stopping the Lab

```bash
# Stop all services
docker-compose down

# Stop all services and remove volumes
docker-compose down -v

# Stop specific service
docker-compose stop dvwa

# Restart a service
docker-compose restart dvwa

# View logs
docker-compose logs -f [service_name]
```

## Troubleshooting

### Port Already in Use
```bash
# Find what's using the port
lsof -i :8080

# Change port in docker-compose.yml
ports:
  - "8081:80"  # Change 8080 to 8081
```

### Container Not Starting
```bash
# Check logs
docker-compose logs [service_name]

# Check container status
docker-compose ps

# Restart service
docker-compose restart [service_name]
```

### Memory Issues
```bash
# Increase Docker memory limit in Docker Desktop settings
# Or start fewer services
docker-compose up -d dvwa mysql_weak ssh_weak
```

### Network Issues
```bash
# Rebuild network
docker-compose down
docker network prune
docker-compose up -d
```

## Recommended Tools

Install these tools on your host machine for testing:

### Kali Linux Tools
```bash
# Information Gathering
nmap, netdiscover, recon-ng

### Web Application Testing
burpsuite, owasp-zap, sqlmap, nikto, dirb, gobuster

### Exploitation
metasploit-framework, searchsploit

### Password Attacks
john, hashcat, hydra, medusa

### Network Attacks
wireshark, tcpdump, bettercap

### Forensics
autopsy, binwalk, strings
```

### Install on Other Distributions
```bash
# Ubuntu/Debian
sudo apt install nmap nikto sqlmap gobuster hydra john

# macOS
brew install nmap sqlmap nikto hydra

# Or use a Kali VM for best compatibility
```

## Learning Resources

- **OWASP**: https://owasp.org
- **HackTheBox**: https://hackthebox.com
- **TryHackMe**: https://tryhackme.com
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **Exploit-DB**: https://exploit-db.com
- **CVE Details**: https://cve.mitre.org

## Safety Checklist

- [ ] Lab is running on isolated network (not exposed to internet)
- [ ] No production data in containers
- [ ] Firewall rules prevent external access
- [ ] Strong passwords on host machine
- [ ] Docker daemon not exposed to network
- [ ] Understanding of legal implications
- [ ] Written authorization for testing (when applicable)

## Disclaimer

This lab environment is created for educational purposes to help security professionals learn ethical hacking techniques in a safe, controlled environment. The author assumes no liability for misuse of this environment. Always ensure you have proper authorization before testing any systems.

## Contributing

Feel free to add more vulnerable services, custom challenges, or improvements. Submit issues and pull requests to help make this lab better for everyone learning ethical hacking.

## License

This project is for educational purposes. Use responsibly and ethically.

---

**Happy Learning and Happy Hacking! Remember: With great power comes great responsibility.**
