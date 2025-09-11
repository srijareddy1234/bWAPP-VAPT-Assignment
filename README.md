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

# SSL/TLS Assessment Report  
<img width="1378" height="658" alt="image" src="https://github.com/user-attachments/assets/95c01f65-b85f-42dd-b8ae-166d827bd4d2" />

**Target:** [http://www.itsecgames.com/](http://www.itsecgames.com/)  

---

## Issue: Missing SSL/TLS Configuration  
- **Severity:** High  
- **Status:** The website does not support HTTPS and no SSL/TLS certificate is deployed.  

---

## Findings
- No HTTPS support  
- No SSL/TLS certificate configured  
- All traffic is unencrypted (plaintext)  
- No server authenticity or trust validation  

---

## Risks
- **Confidentiality:** Data can be intercepted (eavesdropping).  
- **Integrity:** Requests and responses may be modified in transit.  
- **Authentication:** Users cannot verify they are connecting to the legitimate server.  
- **Trust:** Modern browsers flag the site as *Not Secure*.  

---

## Recommendation
- Deploy HTTPS with a valid SSL/TLS certificate (e.g., Let’s Encrypt).  
- Enforce TLS 1.2 and TLS 1.3 only; disable insecure protocols.  
- Use strong cipher suites with forward secrecy.  
- Configure **HSTS (HTTP Strict Transport Security)** to enforce secure connections.  
- Set up certificate renewal and monitor expiry.  

---

## Conclusion
The absence of SSL/TLS leaves the site exposed to interception and man-in-the-middle attacks. Enabling HTTPS with a valid certificate is critical to ensure security and user trust.  

---


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

# A4 - Insecure Direct Object References (IDOR)

## Description
**Insecure Direct Object References (IDOR)** is a common web application vulnerability that occurs when an application exposes internal implementation objects (such as files, database keys, usernames, or account IDs) without proper access control.  

Attackers can manipulate these references to gain **unauthorized access to data** or **perform actions on behalf of other users**.  

This vulnerability is part of the **OWASP Top 10 (A4 - Access Control Issues)**.

---

## Security Level: Low
- A simple text box is provided to update the **secret key**.  
- The request contains the **username** of the logged-in user, which can be intercepted and modified.  

### Example Exploit:
1. Logged in as `bee`.  
2. Intercept the request and modify the `login=bee` parameter to `login=john`.  
3. If a user `john` exists, the attacker can modify **john’s secret key** without having access to his account.  

Proof: By checking the **MySQL database**, we see that the secret of `john` was updated from `bee`’s account.  

### Root Cause:
- The application does not validate whether the logged-in user is authorized to update the requested account.  
- The only validation in the code is a simple character filter (no access control checks).  

---

## Security Level: Medium / High
- In this mode, the application no longer relies on the **login parameter**.  
- Instead, it assigns a **unique random token** to each user for every request.  
- This prevents attackers from tampering with usernames in the request.  

### Example:
- Request is validated against the **session-based token** instead of relying on user-controlled parameters.  
- Any unauthorized modification attempt fails since the token does not match the session of the logged-in user.  

Proof: Source code shows the request validation using **unique tokens**, ensuring proper access control.  

---

## Severity
- **CVSS Score:** 8.7 (High)  
- **Impact:** Account takeover, unauthorized data manipulation.  
- **Attack Vector:** Remote, requires knowledge of other user identifiers.  
- **Priority:** High (should be fixed quickly).  

---

## Remediation
To mitigate IDOR vulnerabilities:

1. **Enforce Access Control**  
   - Always check that the logged-in user is authorized to access or modify the requested resource.  

2. **Avoid Exposing Identifiers**  
   - Do not expose sensitive identifiers (like usernames, IDs) directly in client-side requests.  
   - Use indirect references such as **randomized tokens** or **UUIDs**.  

3. **Session-Based Validation**  
   - Tie sensitive actions to the logged-in session, not user-controlled parameters.  

4. **Least Privilege**  
   - Ensure users can only access their own data and not modify others’.  

5. **Testing**  
   - Perform manual and automated testing to identify IDOR issues.  
   - Tools like **Burp Suite** or **OWASP ZAP** can help identify parameter tampering.  

# HTML Injection

## Description
**HTML Injection** is a type of injection vulnerability that occurs when a web application allows untrusted input to be injected into the HTML response without proper validation or sanitization.  

This can allow an attacker to:
- Steal session cookies or other sensitive information.  
- Impersonate users by hijacking their session.  
- Modify the content of the web page for the victim.  

There are two main types:
- Reflected GET HTML Injection – Input is sent through the URL query parameters.  
- Reflected POST HTML Injection – Input is sent in the body of a POST request instead of the URL.  

---

## Security Level: Low
- Works similar to reflected GET HTML Injection, but payload is delivered via the body of a POST request.  
- Example payload:  
  `script alert('test') /script`  
- The payload is processed and executed in the victim’s browser.  
- Since this uses the POST method, no parameter is shown in the URL.  

---

## Security Level: Medium
- At this level, the application attempts to filter malicious input.  
- The application returns back the encoded payload.  
- By encoding the payload (`script alert('test') /script`), an attacker can bypass filters.  
- Example: passing the encoded payload through the `lastname` parameter in the POST request still results in execution of the injected code.  

---

## Severity
- CVSS Score: 6.1 (Medium) – may escalate depending on impact.  
- Impact:  
  - Stealing user cookies.  
  - Modifying the content of the web page.  
  - Redirecting users to malicious websites.  
- Priority: Medium (requires remediation to prevent session hijacking or phishing attacks).  

---

## Remediation
1. Input Validation and Sanitization  
   - Filter and validate all user input on both client-side and server-side.  
   - Remove or encode special HTML characters (`<`, `>`, `"`, `'`, `/`).  

2. Output Encoding  
   - Apply proper output encoding before displaying user-supplied data in HTML pages.  

3. Content Security Policy (CSP)  
   - Implement a CSP header to restrict the execution of inline scripts.  

4. Avoid Dynamic HTML Generation  
   - Do not concatenate untrusted input directly into HTML responses.  
   - Use safe templating engines that automatically escape user input.  

---

# Sensitive Data Exposure – Base64 Encoding

## Description
Sensitive Data Exposure occurs when applications do not adequately protect sensitive information such as cookies, passwords, tokens, or other confidential data.  
Attackers can intercept, decode, or decrypt weakly protected data and gain access to sensitive information.

In this example, BWAPP demonstrates how weak encoding mechanisms like Base64 or unsalted hashes can expose data.

---

## Security Level: Low

**Step 1:** Open BWAPP, select "Base64 Encoding" and click on Hack.  
**Step 2:** Capture the request in Burp Suite. A `cookie-header` and a parameter named `secret` are observed.  
**Step 3:** The hint suggests decoding the parameter. Using BurpSuite’s `smart decoder`, identify the type of encoding. In this case, it is **Base64**.  
**Step 4:** Select Base64 decoding. The message is revealed as:  

```
Any bugs?
```

This shows sensitive data is exposed due to weak encoding.

---

## Security Level: Medium / High

**Step 1:** Capture the request in Burp Suite. This time, the encoded value is longer and appears more complex.  
**Step 2:** Use a hash analyzer to determine the type of hash. It is identified as **SHA-1** with a bit length of 160.  
**Step 3:** Decrypt or brute force the hash to retrieve the original sensitive data.  

This demonstrates how storing sensitive data with weak or outdated cryptographic functions can still lead to exposure.

---

## Severity
- CVSS Score: 7.5 (High) – depends on the sensitivity of the exposed data.  
- Impact:  
  - Exposure of sensitive information (cookies, secrets, or authentication tokens).  
  - Risk of unauthorized access to user accounts.  
- Priority: High (must implement strong encryption for sensitive data).  

---

## Remediation
1. Do not use **Base64** or weak hashing functions (like **MD5** or **SHA-1**) for storing or transmitting sensitive data.  
2. Use modern cryptographic algorithms such as **AES-256** for encryption and **SHA-256/SHA-3 with salting and key stretching** for hashing.  
3. Ensure sensitive data is only transmitted over **HTTPS** (TLS/SSL).  
4. Avoid storing sensitive information in client-side components such as cookies or hidden form fields.  
5. Regularly update and review cryptographic libraries to prevent the use of broken algorithms.

# bWAPP – XSS Reflected JSON

## Description
Reflected JSON XSS is a vulnerability that occurs when user input is reflected back inside a JSON response without proper validation or encoding. If the response is interpreted by a browser or a client-side script, an attacker can inject malicious JavaScript that executes in the victim’s browser, potentially leading to data theft, session hijacking, or other client-side attacks.

---

## Severity
- CVSS Score: 6.1 (Medium) – can escalate depending on impact.  
- Impact:  
  - Execution of arbitrary JavaScript in the victim’s browser.  
  - Theft of cookies, tokens, or other sensitive information.  
  - Possible session hijacking and client-side manipulation.  
- Priority: Medium (requires remediation to prevent exploitation).  

---

## Remediation
1. Properly validate and sanitize all user inputs before including them in JSON responses.  
2. Apply output encoding to escape special characters in JSON.  
3. Always return JSON responses with the correct `Content-Type: application/json` header.  
4. Implement Content Security Policy (CSP) to limit the execution of injected scripts.  
5. Avoid directly reflecting user input into responses without strict validation.  

---

# Denial-of-Service (Slow HTTP DoS)

## Description
A Slow HTTP DoS attack is a denial-of-service technique where an attacker sends HTTP requests very slowly, either by transmitting headers or body data in small pieces at long intervals. Since the server keeps the connection open while waiting for the request to complete, multiple slow connections can exhaust available resources, causing the server to become unresponsive to legitimate users.

---

## Proof of Concept

**Step 1:** Download the `slowloris.py` script and unzip it.  

**Step 2:** Navigate to the script’s directory.  

**Step 3:** Run the script against the target IP using the command:  
```
./slowloris.py -p 80 -v 192.168.29.3
```

**Step 4:** Once executed, the attack consumes server resources.  
The target site becomes extremely slow to load and eventually inaccessible, confirming the denial-of-service condition.  

---

## Severity
- CVSS Score: 7.5 (High) – depending on server resources and protections in place.  
- Impact:  
  - Server becomes unresponsive to legitimate traffic.  
  - Potential downtime for web applications and services.  
- Priority: High (should be mitigated immediately).  

---

## Remediation
1. Configure web servers to limit the number of open connections per client.  
2. Set appropriate **timeouts** for incomplete HTTP headers and body data.  
3. Use a **reverse proxy** or **load balancer** (e.g., Nginx, HAProxy) to filter out slow connections.  
4. Deploy a **Web Application Firewall (WAF)** or DoS protection services (e.g., Cloudflare, AWS Shield).  
5. Monitor server logs for abnormal traffic patterns to detect and block slow DoS attempts.  

---



