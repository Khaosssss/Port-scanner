Java Port Scanner (Still under development)
Overview

This project is a feature-rich port scanner written in Java.
It can be used to discover open ports, resolve hostnames, analyze HTTP headers, grab SSL certificate information, and perform light web directory brute forcing.

The tool demonstrates practical use of Java’s networking and I/O libraries, and can generate both console and file-based reports.

Features

Host resolution: Resolves target hostname and IP.

Basic port scan: Scans common well-known services (FTP, SSH, HTTP, HTTPS, MySQL, RDP, etc.).

Intense scan: Scans all ports from 1 to 1024.

Banner grabbing: Attempts to read service banners for open ports.

HTTP header security checks: Tests for headers like CSP, HSTS, X-Content-Type-Options, X-Frame-Options.

Cookie security analysis: Detects presence of Secure and HttpOnly flags.

SSL certificate inspection: Retrieves subject, issuer, and expiration date from HTTPS servers.

Directory brute forcing: Checks for common web paths based on a supplied wordlist.

Report saving: Optionally writes scan results to a file.

Requirements

Java 11 or higher

Internet connection to reach the target host

Compilation

Compile the scanner with:

javac PortScanner.java

Usage
Basic Scan (common ports)
java PortScanner <target>


Example:

java PortScanner scanme.nmap.org

Basic Scan with Report File
PortScanner.basicScan("scanme.nmap.org", "report.txt");

Intense Scan (ports 1–1024)
PortScanner.intenseScan("192.168.1.1");

Intense Scan with Report File
PortScanner.intenseScan("192.168.1.1", "full_report.txt");

Banner Grabbing
PortScanner.grabBanner("93.184.216.34", 80);

HTTP Header Security Check
PortScanner.checkHTTPHeaders("http://example.com");

Directory Brute Forcing
List<String> wordlist = List.of("admin", "login", "config", "uploads");
PortScanner.bruteForceDirectories("http://example.com", wordlist);

SSL Certificate Information
PortScanner.getSSLCertificate("example.com", 443);

Example Output
Target Domain: scanme.nmap.org
Resolved IP: 45.33.32.156
 [+] Port 22 (SSH) is OPEN
 [+] Port 80 (HTTP) is OPEN

[HTTP Security Header Check]
 [-] Content-Security-Policy is MISSING
 [+] Strict-Transport-Security is PRESENT
 [-] X-Content-Type-Options is MISSING
 [-] X-Frame-Options is MISSING

[Cookie Security Check]
 Cookie: PHPSESSID
  [+] Secure flag present
  [-] Missing HttpOnly flag

[SSL Certificate]
 Subject: CN=example.com
 Issuer: CN=R3, O=Let's Encrypt, C=US
 Expiry: Sat Dec 21 23:59:59 UTC 2025

Notes

Running scans against systems you do not own or lack explicit permission to test may be illegal.

The tool is intended for educational and security research purposes only.

Some checks (like banner grabbing or brute forcing) may trigger intrusion detection systems.

Directory brute forcing requires you to supply your own wordlist.

License

This project is licensed under the MIT License
