
<p align="center">
  <img src="./screenshots/tryhackme-icon.svg" alt="logo" width="120" />
</p>

<h1 align="center"> TryHackMe: Thompson </h1>

<div align="center">

During the attack, reconnaissance was performed using `nmap`, which led to the identification of an exposed `Apache Tomcat web server`. Access to the application management
interface was obtained through `brute forcing default credentials`. A malicious `.war` file was then `generated and deployed`, resulting in `remote access to the server`.
Further enumeration revealed a `cron job` executing a script with insecure permissions. Exploitation of this misconfiguration ultimately led to `full system compromise`.

</div>
