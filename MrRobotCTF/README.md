
<div align="center">

<img src="./screenshots/tryhackme-icon.svg" alt="logo" width="120"/>

# TryHackMe: Mr Robot CTF

### 📊 Difficulty: **Medium**
### 📁 Category: Web / PrivEsc / Password Attacks / Linux

</div>

---

<div>

🔎 In this engagement, the target system `Mr Robot CTF` was fully compromised.

Initial reconnaissance and service discovery revealed the presence of WordPress-related endpoints, as well as a `robots.txt` file containing the
`first flag` and a `wordlist` later used for credential attacks against the `wp-login.php` authentication portal. Valid credentials were obtained
through a `brute force attack`, providing access to the WordPress administrative interface.

Leveraging legitimate CMS functionality, the `Theme Editor` was abused to inject malicious PHP code into a server-side template, resulting in remote
code execution and establishing a persistent foothold on the system.

Subsequent enumeration uncovered a file within the `robot` user's home directory containing an `unsalted MD5 password hash`. The hash was exfiltrated and
cracked offline, enabling access to the local `robot` account and retrieval of the `second flag`.

Further privilege escalation was achieved by identifying an `nmap` executable with the `SUID bit set`. This binary was then leveraged to obtain a root shell.

</div>
