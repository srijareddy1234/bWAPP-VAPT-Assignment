# SQL Injection

**Category (OWASP 2021):** A03:2021 – Injection  
**Severity:** High  
**Tools Used:** Burp Suite, Browser Developer Tools, SQLmap  

---

## Description
SQL Injection allows attackers to manipulate backend SQL queries by injecting malicious input. In bWAPP, several pages are vulnerable to SQL Injection (GET and POST).

---

## Steps Taken / Exploit Process
1. Logged in to bWAPP with:
   - Username: `bee`
   - Password: `bug`
2. Navigated to the **SQL Injection** module (`SQL Injection (GET/Search)`).
3. Captured the request using Burp Suite Repeater.
4. Tested input fields with common SQL payloads, e.g., `' OR 1=1 -- -`.
5. Observed database error messages and successful query manipulation.
6. Used SQLmap for automated exploitation:
```bash
sqlmap -u "http://127.0.0.1/bWAPP/sqli_1.php?title=1" --cookie="PHPSESSID=YOUR_SESSION_ID; security_level=0" --dbs
