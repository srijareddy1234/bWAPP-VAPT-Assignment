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




