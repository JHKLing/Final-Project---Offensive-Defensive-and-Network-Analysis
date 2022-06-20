# Network Forensic Analysis Report


**Time Thieves**

At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:

- They have set up an Active Directory network.
- They are constantly watching videos on YouTube.
- Their IP addresses are somewhere in the range 10.6.12.0/24.
You must inspect your traffic capture to answer the following questions:

Following Wireshark Filters were Used:

- Domain of the custom site: ip.addr == 10.6.12.0/24
- Traffic Inspection: ip.addr == 10.6.12.12
- Other Traffic Inspection: ip.addr == 10.6.12.203
- Malware Name: ip.addr == 10.6.12.203 and http.request.method == GET

1. What is the domain name of the users' custom site?
- Domain Name: Frank-n-Ted-DC. frank-n-ted.com
- Wireshark Filter: ip.src==10.6.12.0/24
![domain name](./Day 2/1a.png)
   
2. What is the IP address of the Domain Controller (DC) of the AD network?
- IP Address: 10.6.12.12 (Frank-n-Ted-DC.frank-n-ted.com)
- Wireshark Filter: ip.src==10.6.12.0/24
![IP of the DC of AD](./Day 2/1b.png)
 
3. What is the name of the malware downloaded to the 10.6.12.203 machine? Once you have found the file, export it to your Kali machine's desktop.
- Malware file name: june11.dll
- Wireshark Filter: ip.addr == 10.6.12.0/24 and http.request.method == GET
![name of the malware](./Day 2/1c.png)
 
4. Upload the file to VirusTotal.com. What kind of malware is this classified as?
Steps:
1. Exporting file to Kali:
2. Open File Tab
3. Export Objects
4. Select HTTP
5. Filter “*.dll”
6. Save june.dll
7. Upload to VirusTotal.com
![the dll](./Day 2/june-dll.png)
![virustotal.com](./Day 2/virus-total.png)


5. What kind of malaware is this classified as?
 
**Vulnerable Windows Machines**
The Security team received reports of an infected Windows host on the network. They know the following:
Machines in the network live in the range 172.16.4.0/24.
The domain mind-hammer.net is associated with the infected computer.
The DC for this network lives at 172.16.4.4 and is named Mind-Hammer-DC.
The network has standard gateway and broadcast addresses.
Inspect your traffic to answer the following questions:

Following Wireshark Filters were Used:

- Host Name, IP Address, MAC Address: ip.addr == 172.16.4.0/24
- Traffic Inspection: ip.src == 172.16.4.4 && kerberos.CNameString
- Username: ip.src == 172.16.4.205 && kerberos.CNameString
- Malicious Traffic: ip.addr == 172.16.4.205 && ip.addr == 185.243.115.84

1. Find the following information about the infected Windows machine:
- Host name:ROTTERDAM-PC
- IP address:172.16.4.205
- MAC address:172.16.4.205
- Wireshark Filter: ip.addr == 172.16.4.0/24
![Infected machine](./Day 2/2a.png)
!{Infected machine](./Day 2/2b.png)

2. What is the username of the Windows user whose computer is infected?
- Username: matthijs.devries
- Wireshark Filter: ip.src==172.16.4.205 && kerberos.CNameString
![username](./Day 2/2c.png)
 
3. What are the IP addresses used in the actual infection traffic?
- Filter: ip.src==172.16.4.203 and kerberos.CNameString
- Found 4 IP addresses: 172.16.4.205, 185.243.115.84, 166.62.11.64 and 23.43.62.169
- Finding the IP addresses:
~ Click on the Statistics Tab
~ Select the Conversation
~ Select the IPv4
~ Sort Packets high to low
![Actual ifected traffic](./Day 2/2d.png)
 
4. As a bonus, retrieve the desktop background of the Windows host.
![background](./Day 2/2e.png)
![background](./Day 2/2f.png)


**Illegal Downloads**
IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement.

IT shared the following about the torrent activity:
- The machines using torrents live in the range 10.0.0.0/24 and are clients of an AD domain.
- The DC of this domain lives at 10.0.0.2 and is named DogOfTheYear-DC.
- The DC is associated with the domain dogoftheyear.net.

Following Wireshark Filters were Used:

- MAC Address: ip.addr == 10.0.0.201 && dhcp
- Username: ip.src == 10.0.0.201 && kerberos.CNameString
- Operating System: ip.addr == 10.0.0.201 && http.request
- Torrent Download: ip.addr == 10.0.0.201 && http.request.method == "GET"

Your task is to isolate torrent traffic and answer the following questions:

1. Find the following information about the machine with IP address 10.0.0.201:
- MAC address: 00:16:17:18:66:c8
- Windows username: elmer.blanco
- OS version: BLANCO-DESKTOP Windows NT 10.0
- Wireshark Filter for MAC Address: ip.addr == 10.0.0.201 && dhcp
![MAC address](./Day 2/3a.png)
- Wireshark Filter for Username: ip.addr == 10.0.0.201 && kerberos.CNameString
![Filter](./Day 2/3b.png)
- Wireshark Filter for OS Type and Version: ip.addr == 10.0.0.201 && http.request
![OS](./Day 2/3c.png)

2. Which torrent file did the user download?
- There were few that were downloaded, but below clip was show with the name:
Betty_Boop_Rhythm_on_the_Reservation.avi.torrent
- Wireshark Filter: ip.addr == 10.0.0.201 && http.request.method == "GET"
- Finding the torrent:
~ Apply the Wireshark Filter above.
~ Sort the packets by the Destination files.publicdomaintorrents.com (168.215.194.14).
~ Look for Download requests.
![download request](./Day 2/3d.png)
![download request](./Day 2/3e.png)
![download request](./Day 2/3f.png)
![download request](./Day 2/3g.png)

