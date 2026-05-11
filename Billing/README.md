
<p align="center">
  <img src="./screenshots/billing_icon.png" alt="icon" width="120" />
</p>

<h1 align="center"> TryHackMe: Billing </h1>

<h3 align="center">

Отчет по реализации атаки на систему <code>Billing</code>

</h3>

<br>

<div>

Исследуем VoIP/billing систему <code>MagnusBilling</code> и обнаружим unauthenticated <code>Command Injection</code> (<code>CVE-2023-30258</code>). Разберемся, каким образом параметр <code>democ</code> приводит к выполнению
произвольных shell команд через PHP <code>exec()</code>. Подтвердим наличие <code>RCE</code> через blind command execution и получим первоначальный доступ в систему.

</div>

<br>

<div>

После закрепления в системе проведем локальную разведку и обнаружим небезопасную конфигурацию <code>sudoers</code> для пользователя <code>asterisk</code>, позволяющую управлять интерфейсом <code>fail2ban-client</code> от имени
любого пользователя. Разберемся во внутреннем устройстве инструмента <code>fail2ban</code>, механизме его работы и используем возможность изменения параметра <code>actionban</code> у action <code>iptables-multiport</code> для
выполнения произвольных команд с <code>root</code> привилегиями, тем самым полностью скомпрометировав систему.

</div>

