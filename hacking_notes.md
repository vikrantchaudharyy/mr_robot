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


# Network Penetration Testing/Hacking
- Pre Connection attack
- Gaining Access
- Post connection attack

## change Mac address
- Increase anonymity
- Impersonate other devices
- Bypass filters
- steps:
  - ifconfig (look for the newly added adapter, ex: wlan0), need to change the ether field
  - disable network -> ifconfig wlan0 down
  - ifconfig waln0 hw ether 11:22:33:44:55
  - enable network -> ifconfig wlan0 up
  - check -> ifconfig
  - it will reset after restarting


## Change to Monitor mode
- by default device only listens data which has the mac address in destination fields of the messages
- capture all the data transferred in the air within range by changing to Monitor mode
- steps:
  - iwconfig -> to see wireless interface only
  - by default mode is Managed mode
  - ifconfig waln0 down
  - kill any process which may interfere in Monitor mode (kills all connection but connection not required in pre-connection attacks)
    - command -> airmon-ng check kill
  - iwconfig wlan0 mode monitor
  - ifconfig wlan0 up
  - check -> iwconfig

# Pre-connection attack
## Packet Sniffing (Using Airodump-ng)
- Part of the aircrack-ng suit.
- Airodump-ng is a packet sniffer;
- Used to capture all packets within range.
- Display detailed info about networks around us.
- Connected clients ….etc
- use:
  - check network interfere name -> iwconfig
  - airodump-ng [MonitorModeInterface]
  - https://tools.kali.org/wireless-attacks/airodump-ng
  - output details -> https://www.aircrack-ng.org/doku.php?id=airodump-ng
  - airodump-ng --band a [MonitorModeInterface] (capture 5gz frequency)
  - airodump-ng --band abg [MonitorModeInterface] (capture 2.4gz and 5gz frequency both)

## Network Hacking - Sniffing data for single Network device
- airodump-ng mon0
- airodump-ng -bssid FC:15:B4:00:00:00 --channel 2 --write test mon0
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
  - aireplay-ng --deauth [#DeauthPackets] -a [NetworkMac] -c [TargetMac] [Interface]
  - airodump-ng --deauth 10000000 -a FC:15:B4:00:00:00 -c FF:FF:FF:00:00:00 mon0
  - https://tools.kali.org/wireless-attacks/aireplay-ng
- theory:
  - Impersonate as client to access point(router) to Disconnect (by changeing self mac to client mac)
  - Impersonate as access point(router) to client to disconnect on client request (changing mac to router's mac)

##Gaining Access - WEP Cracking
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
  - airodump-ng -bssid FC:15:B4:00:00:00 --channel 1 --write basic_wep mon0
  - aircrack-ng basic_wep-01.cap
  - use Ascii key or hex key with all semicolon removed to connection to device


## Fake Authentication Attack
- If network is not busy -> we need Force the AP(Access Point) to generate new IVs (Fake Authentication)
- we need to associate to the Network (tell the network that we want to communicate with it, by default access point ignore requests they get unless the device is connected to them or associated with it)
- command:
  - monitor -> airodump-ng -bssid FC:15:B4:00:00:00 --channel 1 --write arp_replay mon0
  - run attack -> aireplay-ng --fakeauth 0 -a FC:15:B4:00:00:00 -h 11:22:33:44:55:55 mon0
  - FC:15:B4:00:00:00 is the target access point
  - 11:22:33:44:55 my wireless adapter mac address
  - can get: ifconfig ->  first 12 digitals of unspec field, replace - with :


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
-
