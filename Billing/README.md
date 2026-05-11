
<p align="center">
  <img src="./screenshots/billing_icon.png" alt="icon" width="120" />
</p>

<h1 align="center"> TryHackMe: Billing </h1>

<h3 align="center">

Attack Implementation Report for the Billing System

</h3>

<br>

<div>

We investigate the MagnusBilling VoIP/billing platform and identify an unauthenticated Command Injection vulnerability (CVE-2023-30258). We analyze how the democ parameter leads to arbitrary shell command
execution through the PHP exec() function. After confirming the presence of remote code execution (RCE) via blind command execution, we obtain initial access to the system.

</div>

<br>

<div>

After establishing access to the system, we perform local enumeration and identify an insecure sudoers configuration for the asterisk user, allowing the fail2ban-client interface to be managed as any user on the system.
We then examine the internal architecture and operational logic of Fail2Ban and abuse the ability to modify the actionban parameter within the iptables-multiport action to execute arbitrary commands with root privileges,
ultimately resulting in full system compromise.

</div>

