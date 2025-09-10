# bWAPP-VAPT-Assignment
VAPT assignment using bWAPP - documenting vulnerabilities, PoC, and mitigation.

## Assignment Objective

- Identify and exploit multiple web vulnerabilities.
- Document each vulnerability with Proof of Concept (PoC), findings, and mitigation.
- Assess security configurations such as SSL/TLS, headers, and misconfigurations.

---

## Tools Used

- **Burp Suite** (Proxy, Repeater, Scanner)
- **SQLmap** (SQL Injection testing)
- **Browser Developer Tools**
- **bWAPP Docker container**

---

## Setup Instructions (Docker)

# bWAPP Docker

A simple Docker image for the **OWASP bWAPP** application designed demonstrate various web application vulnerabilities.

---

## Why?

Installing and configuring PHP-based web apps can be quite time-consuming as you need to install various packages like **PHP, Apache, MySQL**, etc.  

I chose option since it is much eaiser to set up the BWAPP Application

---

## Setup

### Pull the Docker image
This repo provides you with a prebuilt Docker image that you can pull and run in seconds:

```bash
docker pull hackersploit/bwapp-docker
```
### Running the bWAPP container
Start the container with:
```
docker run -d -p 80:80 hackersploit/bwapp-docker
```
### Installing bWAPP
After running the container, navigate to:
```
http://127.0.0.1/install.php
```
to complete the bWAPP setup process.

<img width="955" height="667" alt="ss-4-bwaapploginpage" src="https://github.com/user-attachments/assets/204a839f-115a-47b7-b62a-78b6e8054c15" />

# OS Command Injection

## Description
**OS Command Injection** (also known as *Shell Injection*) is a critical web security vulnerability that occurs when an application insecurely passes user-supplied input into a system command.  
This allows an attacker to execute arbitrary operating system commands on the server hosting the application, potentially leading to a **full system compromise**.  

Attackers can:
- Access sensitive data stored on the server.
- Pivot to other systems within the infrastructure.
- Escalate privileges and gain persistent access.
- Exploit trust relationships to launch further attacks.

---

## Demo
**Security level:** `Low`

- The input provided by the user is executed directly in the shell.
- Exploitation can be achieved by appending commands using operators like:
  - `|` (pipe)  
  - `;` (semicolon)  
  - `&&` (AND operator)  

### Example:
Appending `| ls` to the input executes the `ls` command on the server.  

- When intercepting the request, we can see that the **`target` parameter** is vulnerable.  
- The server executes our malicious input and returns the output from the shell.

---

## Severity
- **CVSS Score:** **9.8 (Critical)**  
- **Impact:** Remote Code Execution (RCE)  
- **Attack Vector:** Remote (no authentication required in low-security setups)  
- **Priority:** Must be patched immediately.  

---

## Remediation
To mitigate OS Command Injection vulnerabilities:

1. **Input Validation & Sanitization**  
   - Reject or strictly validate user input before processing.  
   - Allow only expected values (e.g., whitelisting).  

2. **Use Safe APIs / Functions**  
   - Avoid direct calls to system commands like `system()`, `exec()`, `shell_exec()`, or backticks.  
   - Use language-specific safe APIs instead (e.g., database connectors, built-in libraries).  

3. **Principle of Least Privilege**  
   - Run the application with minimal system privileges.  
   - Prevent the web application user from executing sensitive commands.  

4. **Web Application Firewall (WAF)**  
   - Deploy a WAF to detect and block suspicious command injection attempts.  

5. **Code Review & Testing**  
   - Perform secure code reviews.  
   - Use automated tools (e.g., Burp Suite, OWASP ZAP) to test for injection flaws.  





