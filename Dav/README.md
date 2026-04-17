<p align="center">
  <img src="./screenshots/tryhackme-icon.svg" alt="logo" width="120" />
</p>

<h1 align="center"> TryHackMe: Dav </h1>

<div align="center">

123

During the attack on the target system, access to an internal network was obtained via an OpenVPN configuration. After performing reconnaissance and fuzzing, a WebDAV endpoint
was discovered and accessed using default credentials. Misconfigured WebDAV permissions allowed arbitrary file upload, leading to Remote Code Execution through a PHP reverse shell.
Post-exploitation enumeration revealed a misconfigured sudo rule, which was leveraged to escalate privileges and retrieve the root flag.

</div>
