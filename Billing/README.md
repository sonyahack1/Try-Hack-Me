
<p align="center">
  <img src="./screenshots/billing_icon.png" alt="icon" width="120" />
</p>

<h1 align="center"> TryHackMe: Billing </h1>

<h3 align="center">

Attack Implementation Report for the <code>Billing</code> System:

</h3>

<br>

<div>

We investigate the <code>MagnusBilling</code> VoIP/billing platform and identify an unauthenticated <code>Command Injection</code> vulnerability (<code>CVE-2023-30258</code>). We analyze how the democ parameter leads
to arbitrary shell command execution through the PHP <code>exec()</code> function. After confirming the presence of <code>remote code execution (RCE)</code> via blind command execution, we obtain initial access to the system.

</div>

<br>

<div>

After establishing access to the system, we perform local enumeration and identify an insecure <code>sudoers configuration</code> for the asterisk user, allowing the <code>fail2ban-client</code> interface to be managed as
any user on the system. We then examine the internal architecture and operational logic of <code>fail2ban</code> and abuse the ability to modify the <code>actionban</code> parameter within the <code>iptables-multiport</code>
action to execute arbitrary commands with root privileges, ultimately resulting in full system compromise.

</div>

