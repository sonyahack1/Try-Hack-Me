
<p align="center">
  <img src="./screenshots/tryhackme-icon.svg" alt="logo" width="120" />
</p>

<h1 align="center"> TryHackMe: Recruit </h1>

<div align="center">

During the attack, the target was first scanned and fuzzed, which led to the discovery of the <code>mail</code> endpoint. The log file contained a hint that credentials were stored in <code>config.php</code>.

A <code>PHP stream wrapper (file://)</code> was exploited to read this file and obtain user credentials, which were then used to log into the HR system and retrieve the first flag.

Next, a <code>SQL injection</code> vulnerability was exploited to achieve <code>Remote Code Execution (RCE)</code>. During post-exploitation, the <code>db.php</code> file was found, containing MySQL credentials.
These were used to extract administrator credentials from the database, allowing login as an admin and retrieval of the final flag.

</div>
