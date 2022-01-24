---
title: "Fun with ARP - A Look at the Protocol"
published: 2022-01-24T12:00:00-04:00
updated: 2022-01-24T12:00:00-04:00
categories:
  - tutorial
  - programming
tags:
  - network
  - protocol
  - overview
summary: The Address Resolution Protocol (ARP) is an essential part of the TCP/IP protocol suite and will remain in common use as long as IPv4 sticks around. It is a very simple protocol and fun to hack with....
---

The **Address Resolution Protocol (ARP)** ([RFC 826; 1982](https://datatracker.ietf.org/doc/html/rfc826)) is an essential part of the TCP/IP protocol suite and will remain in common use as long as IPv4 sticks around. It is a very simple protocol and fun to hack with.

In theory it can be used to translate any address of a given address system into another address of another address system. These addresses can be of variable byte length.

In modern times ARP is most commonly used to figure out which MAC address (hardware address) is associated with a given IPv4 address (logical address) in an Ethernet network segment.

In such a network every host keeps an ARP table. This table stores the known pairs of MAC and IPv4 addresses for neighboring hosts.

Print ARP table on Linux:

```bash
# On host "Alf"
# MAC: 08-00-27-aa-aa-aa
# IPv4: 10.0.0.1
root@alf:~$ arp -a
? (10.0.0.111) at 08:00:27:cc:cc:cc [ether] on eth0
```

Print ARP table on Windows (cmd):

```bash
# On Host "Bert"
# MAC: 08-00-27-aa-aa-aa
# IPv4: 10.0.0.2
C:\Users\Bert> arp -a

Interface: 10.0.0.2 --- 0x7
  Internet Address    Physical Address     Type
  10.0.0.111          08:00:27:cc:cc:cc    dynamic
  10.0.0.255          ff-ff-ff-ff-ff-ff    static
  255.255.255.255     ff-ff-ff-ff-ff-ff    static
```

In this example both hosts have a common gateway router with IPv4 address `10.0.0.111` and MAC address `08:00:27:cc:cc:cc`.

Let us assume we are in an Ethernet-based local network with several hosts connected via a switch or hub. All hosts in that Ethernet are in the same logical IPv4 network `10.0.0.0/24` and no routing is required in this example.

![Example Network](/assets/img/network_example_simple2.png)

When host Alf (`10.0.0.1`) wants to communicate with host Bert (`10.0.0.2`), then host Alf will first have to figure out the MAC address of host Bert. Otherwise host Alf would not know where to send its Ethernet frames.

Host Alf will first look into its own ARP table to see if it already knows the MAC address associated with the IPV4 address "10.0.0.2". If it already has an entry, then the info can be used directly and the ARP process ends here. But in this case there is no entry for that IPv4 address.

If there is no entry, then host Alf will ask the entire local network: "Which host has IPv4 address 10.0.0.2?"

This **ARP Request** will be sent as the payload of an Ethernet frame. The target MAC Address of this frame will be the broadcast address `ff:ff:ff:ff:ff:ff`. This means the frame is addressed to all hosts in the same LAN segment. All of those hosts should receive it.

```default
[ Ethernet Frame: Source: 08-00-27-aa-aa-aa; Destination: ff-ff-ff-ff-ff-ff; Content: ARP (0x806) ]
    -----------------------------------------------
    | ARP REQUEST                                 |
    -----------------------------------------------
    | HTYPE 0x1 | PTYPE 0x800 | HLEN 6 | PLEN 4   |
    | SHA  08-00-27-aa-aa-aa  | SPA  10.0.0.1     |
    | THA  00-00-00-00-00-00  | TPA  10.0.0.2     |
    -----------------------------------------------

```

* HTYPE - Hardware type (0x1 = Ethernet)
* PTYPE - Protocol Type (0x800 = Ipv4)
* HLEN - Hardware address length (6 Bytes for MAC Address)
* PLEN - Protocol address length (4 Bytes for IPv4 Address)
* SHA - Sender hardware address (08-00-27-aa-aa-aa)
* SPA - Sender protocol address (10.0.0.1)
* THA - Target hardware address (00-00-00-00-00-00 because it is unknown)
* TPA - Target protocol address (10.0.0.2)

If everything goes well, then Bert will receive this ARP Request and send an **ARP Reply** along the lines of: "I have IPv4 address 10.0.0.2 and here is my MAC address". This Reply Ethernet frame will be directed directly at the MAC Address of Alf (unicast).

```default
[ Ethernet Frame: Source: 08-00-27-bb-bb-bb; Dest: 08-00-27-aa-aa-aa; Content: ARP (0x806) ]
    -----------------------------------------------
    | ARP REPLY                                   |
    -----------------------------------------------
    | HTYPE 0x1 | PTYPE 0x800 | HLEN 6 | PLEN 4   |
    | SHA  08-00-27-bb-bb-bb  | SPA  10.0.0.2     |
    | THA  08-00-27-aa-aa-aa  | TPA  10.0.0.1     |
    -----------------------------------------------
```

Alf will receive this Reply and update its ARP table accordingly:

```bash
root@alf:~$ arp -a
? (10.0.0.111) at 08:00:27:cc:cc:cc [ether] on eth0
? (10.0.0.2) at 08:00:27:bb:bb:bb [ether] on eth0
```

Afterwards Alf can communicate with `10.0.0.2` (Bert).

In the example above Bert will usually also add or update an entry for Alf in its own ARP table when it receives Alf's ARP Request. 

So one ARP handshake tends to updates the tables of both hosts. Otherwise Bert would have to send out its own ARP Request in order to figure out the MAC address associated with `10.0.0.1` (Alf). Which would create unnecessary network traffic.


## No Security

You might have noticed that in this process there is no mechanism that would ensure that the host that answers Alf's request is actually Bert and not some imposter. And you are right, there is none.

Similarly you can also usually update the tables of other hosts simply by **sending them an ARP Request**. In that Request you can pretend to speak for any IPv4 address. This will usually also overwrie any existing dynamic ARP table entries for that IPv4 address.

Depending on the implementation of ARP, an **unsolicited ARP Reply** might have the same effect. "Unsolicited" means the target host never sent out an ARP Request that would warrant the ARP Reply. From my experience most Linux distributions usually ignore unsolicited Reply messages. Same with modern Windows versions. But the pfsense (FreeBSD) VM used below did accept them and updated their table accordingly.


The two methods mentioned above are commonly exploited in the form of **man-in-the-middle attacks**, usually referred to as "ARP Spoofing" or "ARP cache poisoining".

There are some defense strategies to address this. 

One strategy is to **manually set static ARP entries** in the ARP tables of all the hosts and disabling the dynamic ARP Reply/Response system. This obviously defeats the whole point of ARP and quite often leads to unsustainable administrative effort. In very small network segments that rarely change this might be a good idea though.

Other strategies involve **automatic detection systems** for suspicious ARP activity. For example [arpwatch](https://en.wikipedia.org/wiki/Arpwatch) or [ArpON](https://en.wikipedia.org/wiki/ArpON) to name some free ones.


When you **manually look** for indications of spoofing, then an obvious hint is the existence of **several IPv4 addresses associated with the same MAC address**. This must not *necessarily* mean there is spoofing going on, but it is a pretty good inidcator. An easy way for an attacker to circumvent this is to use a fictional MAC address for spoofing and relaying. Alternatively an attacker could deactivate dynamic ARP on their host before connecting to the network. They could also just wait for existing ARP entries to time out before starting the spoofing after deactivating dynamic ARP.


## Implementation Differences

Besides the Request/Reply handshake and the existence of an ARP table, the specification of the protocol ([RFC 826; 1982](https://datatracker.ietf.org/doc/html/rfc826)) leaves a lot of room for custom implementations.

Depending on the implementation, the entries of the ARP table are usually only considered valid or trustworthy for a limited amount of time. After some time they will get removed or are considered stale. In newer Windows versions this time is usually somewhere between 15 to 45 seconds (random factor is involved).

In some implementations entries might get refreshed automatically in regular intervals. For that the host will send regular ARP requests to the known neighbors in the table. The Ethernet frames of those ARP Requests will be addressed directly to the known MAC address of the neighbor in the ARP table, rather than using a broadcast MAC address. Depending on the answer (or the lack thereof) the local ARP table will be updated. 

The RFC 826 discusses these design decisions in the "Related issue" section at the bottom of the document.


## Getting Practical

Let us take a more practical look at ARP. Create some VM's of your choosing in VirtualBox (or some other virtualization software) and assign them to the same internal network.

You can of course re-use some VMs you already have.

I mirrored the example above, plus I added a Kali VM that I will use to test the behavior of the other VMs:

![Network Lab](/assets/img/arp_vms.png)

* **Alf** ([Debian Linux 11](https://www.debian.org/download)) - `08:00:27:AA:AA:AA` - `10.0.0.1 /24`
* **Bert** ([Windows 11](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)) - `08:00:27:BB:BB:BB` - `10.0.0.2 /24`
* **Middleman** ([Kali Linux](https://www.kali.org/get-kali/) or some other Linux distro) - `08:00:27:DD:DD:DD` - `10.0.0.42 /24`
* **Gateway** ([pfSense FreeBSD](https://www.pfsense.org/)) - `08:00:27:CC:CC:CC` - `10.0.0.111 /24`

You can add them to a shared internal network and change the MAC addresses in the network config of the VMs.

I named my shared internal network "arp_net":

![Alf Adapter config](/assets/img/arp_network_config.png)

Configure Bert and Middleman like this as well.

I assume you know how to install the operating systems and set a static IPv4 address inside of those VMs. I assigned them IPv4 addresses as listed above and configured `10.0.0.111` as the default gateway.

For the pfSense router I created two network interfaces. One in the internal network configured as listed above (08:00:27:CC:CC:CC - 10.0.0.111), the other interface being set to "Bridged Adapter" mode. 

![Gateway Adapter config](/assets/img/gateway_network_config.png)

When you configure pfSense via terminal, set the bridged adapter as the WAN interface. You should probably change the password of the web interface or disable it.


### Byte Tables

Here are the byte tables for ARP and Ethernet frames:

<table class="protocol">
  <thead>
    <th class="table-header" colspan="5">Ethernet II Frame</th>
  </thead>
  <thead>
    <th>MAC Destination</th>
    <th>MAC Source</th>
    <th>Ethertype</th>
    <th style="background-color: #999;">Payload</th>
    <th>Frame Check 32‑bit CRC</th>
  </thead>
  <tr>
    <td>6 Bytes</td>
    <td>6 Bytes</td>
    <td>2 Bytes</td>
    <td style="background-color: #ccc;">46‑1500 Bytes</td>
    <td>4 Bytes</td>
  </tr>
  </table>

**ARP** for Ethernet and Ipv4 is very small and **will only take up 28 bytes of the frame payload section**. The minimum frame payload size is 46 bytes though. This means the remaining 18 bytes of the payload section will be padded with zeroed bytes (0x00) or junk data.


<table class="protocol">
  <thead>
    <th class="table-header" colspan="4">Address Resolution Protocol (ARP)</th>
  </thead>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#48a2ccaa;">Byte 0</th>
    <th style="background-color:#48a2ccaa;">Byte 1</th>
  </thead>
  <tr>
    <td style="background-color:#7dcbf0aa;" colspan="2"><b>Hardware type (HTYPE)</b> <br>[expected: 0x2 for Ethernet]</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#82a451aa;">Byte 2</th>
    <th style="background-color:#82a451aa;">Byte 3</th>
  </thead>
  <tr>
    <td style="background-color:#b9c6a6aa;" colspan="2"><b>Protocol type (PTYPE)</b> <br>[expected: 0x800 for Ipv4]</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#48a2ccaa;">Byte 4</th>
    <th style="background-color:#82a451aa;">Byte 5</th>
  </thead>
  <tr>
    <td style="background-color:#7dcbf0aa;"><b>Hardware address length (HLEN)</b> <br>[expected: 0x6]</td>
    <td style="background-color:#b9c6a6aa;"><b>Protocol address length (PLEN)</b> <br>[expected: 0x4]</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th>Byte 6</th>
    <th>Byte 7</th>
  </thead>
  <tr>
    <td colspan="2"><b>Operation (OPER)</b> <br>[0x1 = Request; 0x2 = Reply]</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#48a2ccaa;">Byte 8 - Byte 13 (~6 bytes)</th>
  </thead>
  <tr>
    <td style="background-color:#7dcbf0aa;">Sender hardware address (SHA)</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#48a2ccaa;">Byte 14 - Byte 17 (~4 bytes)</th>
  </thead>
  <tr>
    <td style="background-color:#7dcbf0aa;">Sender protocol address (SPA)</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#82a451aa;">Byte 18 - Byte 23 (~6 bytes)</th>
  </thead>
  <tr>
    <td style="background-color:#b9c6a6aa;">Target hardware address (THA)</td>
  </tr>
</table>
<table class="protocol">
  <thead>
    <th style="background-color:#82a451aa;">Byte 24 - Byte 27 (~4 bytes)</th>
  </thead>
  <tr>
    <td style="background-color:#b9c6a6aa;">Target protocol address (TPA)</td>
  </tr>
</table>

The above first 8 bytes of an ARP message are static in length. It is followed by the address section.

The address section **can differ in length based on the values of HLEN and PLEN**. 

But in the expected use case with MAC addresses and IPv4 addresses it will be 6 bytes and 4 bytes respectively for Sender and Target.


### Logging Ethernet and ARP

You can of course log ARP in tcpdump or Wireshark.

But I will re-use some code that I used for [my article about writing a network sniffer from scratch](https://secoats.github.io/posts/ethernet_sniffer.html). If you require more details about the libraries and network constants that I am going to use, then check out that article.

This code will also be used in the next part of this series about ARP Spoofing.

I hacked together this listener for ARP and the Ethernet frames that transport it:


```python
#!/usr/bin/env python3
# 0A75
# arpfun.py
import struct
import socket
import datetime

ETHER_TYPE_DICT = {
    0x0800: "Internet Protocol version 4 (IPv4)",
    0x0806: "Address Resolution Protocol (ARP)",
    0x86DD: "Internet Protocol Version 6 (IPv6)",
}

ETHER_TYPE_DICT_INVERS = {
    "IPv4": 0x0800,
    "ARP": 0x0806,
    "IPv6": 0x86DD
}

ARP_OPERATION_DICT = {
    "REQUEST": 0x01,
    "REPLY": 0x02
}

ARP_HTYPE_DICT = {
    "ETHERNET": 0x01,
    "IEEE_802": 0x06,
    "ARCNET": 0x07,
    "FRAME_RELAY": 0xf,
    "ATM": 0x10,
    "SERIAL": 0x14
}

class bcolors:
    CRED    = '\33[31m'
    CGREEN  = '\33[32m'
    CYELLOW = '\33[33m'
    CBLUE   = '\33[34m'
    CBEIGE  = '\33[36m'
    CBEIGE2  = '\33[96m'
    OKBLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def green(text):
    return bcolors.CGREEN + str(text) + bcolors.ENDC

def blue(text):
    return bcolors.CBLUE + str(text) + bcolors.ENDC

def blue2(text):
    return bcolors.OKBLUE + str(text) + bcolors.ENDC

def blue3(text):
    return bcolors.CBEIGE2 + str(text) + bcolors.ENDC

def blue4(text):
    return bcolors.CBEIGE + str(text) + bcolors.ENDC

def red(text):
    return bcolors.CRED + str(text) + bcolors.ENDC

def mac_to_str(data):
    octets = []
    for b in data:
        octets.append(format(b, '02x'))
    return "-".join(octets)

def ipv4_to_str(data):
    octets = []
    for b in data:
        octets.append(format(b, 'd'))
    return ".".join(octets)

def str_to_mac(macstr):
    mac_as_bytes = bytes.fromhex(macstr.replace('-', ''))
    return mac_as_bytes

def str_to_ipv4(ipstr):
    ip_as_bytes = bytes(map(int, ipstr.split('.')))
    return ip_as_bytes

def unpack_ethernet_frame(raw_data):
    DEST_MAC, SRC_MAC, ETHER_TYPE = struct.unpack('! 6s 6s H', raw_data[:14])
    return EthernetFrame(dest_mac=DEST_MAC, src_mac=SRC_MAC, ether_type=ETHER_TYPE, payload=raw_data[14:])

def pack_ethernet_frame(ethernet_frame):
    header = struct.pack('! 6s 6s H', ethernet_frame.DESTINATION, ethernet_frame.SOURCE, ethernet_frame.ETHER_TYPE)
    payload = ethernet_frame.PAYLOAD
    return header + payload

def unpack_arp_message(raw_data):
    HTYPE, PTYPE, HLEN, PLEN, OPER = struct.unpack('! H H B B H', raw_data[:8])
    SHA, SPA, THA, TPA = struct.unpack('! 6s 4s 6s 4s', raw_data[8:28])
    return ARPMessage(htype=HTYPE, ptype=PTYPE, hlen=HLEN, plen=PLEN, operation=OPER, sha=SHA, spa=SPA, tha=THA, tpa=TPA)

def pack_arp_message(arp_message):

    if(arp_message.HLEN != 6):
        raise Exception("Only supporting HLEN = 6 (MAC)")

    if(arp_message.PLEN != 4):
        raise Exception("Only support PLEN = 4 (Ipv4)")

    header = struct.pack('! H H B B H', arp_message.HTYPE, arp_message.PTYPE, arp_message.HLEN, arp_message.PLEN, arp_message.OPER)
    addresses = struct.pack('! 6s 4s 6s 4s', arp_message.SHA, arp_message.SPA, arp_message.THA, arp_message.TPA)
    return header + addresses

class EthernetFrame:
    def __init__(self, dest_mac, src_mac, ether_type, payload):
        self.DESTINATION = dest_mac
        self.SOURCE = src_mac
        self.ETHER_TYPE = ether_type
        self.PAYLOAD = payload
        self.LOG_TIME = datetime.datetime.now()

    def __str__(self):
        ether = hex(self.ETHER_TYPE)
        trans = "UNKNOWN"

        # Translate EtherType to human readable text
        if self.ETHER_TYPE in ETHER_TYPE_DICT:
            trans = ETHER_TYPE_DICT[self.ETHER_TYPE]

        source = mac_to_str(self.SOURCE)
        dest = mac_to_str(self.DESTINATION)
        length = len(self.PAYLOAD)
        return f"[ Ethernet - {ether} {trans}; Source: {source}; Dest: {dest}; Len: {length}; Logtime: {str(self.LOG_TIME)} ]"

class ARPMessage:
    def __init__(self, htype, ptype, hlen, plen, operation, sha, spa, tha, tpa):
        self.HTYPE = htype
        self.PTYPE = ptype
        self.HLEN = hlen
        self.PLEN = plen
        self.OPER = operation
        self.SHA = sha
        self.SPA = spa
        self.THA = tha
        self.TPA = tpa

    def arp_operation_to_str(self):
        if self.OPER == 1:
            return "REQUEST"
        if self.OPER == 2:
            return "REPLY"
        raise Exception("Unknown ARP operation")

    def __str__(self):
        indent = 2 * " "
        line = "-" * 44

        arp_str = ""
        arp_str += indent + "| " + line + " |\n"
        arp_str += indent + "| {:<44} |\n".format(f"ARP {self.arp_operation_to_str()}")
        arp_str += indent + "| " + line + " |\n"

        table = [
            ( f"HTYPE {hex(self.HTYPE)}", f"PTYPE {hex(self.PTYPE)}" ),
            ( f"HLEN  {hex(self.HLEN)}", f"PLEN  {hex(self.PLEN)}" ),
            ( f"SHA {mac_to_str(self.SHA)}", f"SPA {ipv4_to_str(self.SPA)}" ),
            ( f"THA {mac_to_str(self.THA)}", f"TPA {ipv4_to_str(self.TPA)}" ),
        ]

        for a,b in table:
            arp_str += indent + "| {:<22} | {:<19} |\n".format(a,b)

        arp_str += indent + "| " + line + " |\n"
        return arp_str

def main():
    # create raw ethernet socket
    ETH_P_ALL = 3
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

    # ARP LISTENER
    while True:
        raw_data, addr = sock.recvfrom(65565)
        frame = unpack_ethernet_frame(raw_data)

        # log ARP only
        if frame.ETHER_TYPE == ETHER_TYPE_DICT_INVERS.get("ARP"):
            print(blue2(frame))
            
            arp = unpack_arp_message(frame.PAYLOAD)

            if arp.OPER == ARP_OPERATION_DICT.get("REQUEST"):
                print(green(arp))
            else:
                print(blue4(arp))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReceived interrupt. Exiting...")
```

This script will also serve as a library for other ARP scripts that will follow.


## ARP in Action

After starting the Gateway (pfSense) and Middleman (Kali Linux) we can observe ARP in action.

Start the ARP listener script as root on Middleman in one terminal:

```bash
$ sudo python3 arpfun.py
```

Then open another terminal.

At first the ARP table of Middleman will be empty:

```bash
$ arp -n
<blank>
```


If your ARP table already has entries, then you can empty it with:

```bash
$ sudo ip -s -s neigh flush all

*** Round 1, deleting 1 entries ***
*** Flush is complete after 1 round ***

$ arp -n
<blank>
```

Now, when we try to send a ping to the Gateway the MAC address associated with the IPv4 address is not known, so ARP will have to be performed first:

```bash
$ ping -c 1 10.0.0.111
PING 10.0.0.111 (10.0.0.111) 56(84) bytes of data.
64 bytes from 10.0.0.111: icmp_seq=1 ttl=64 time=0.753 ms
```

While the ping command runs we can observe the ARP handshake in the listener console:

![Middleman's ARP Request to Gateway](/assets/img/00_middleman_basic_arp_to_gateway.png)


After a successful handshake there will be an entry for Gateway in Middleman's ARP table:

```bash
$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.0.111               ether   08:00:27:cc:cc:cc   C                     eth0
```

The Gateway (pfSense VM) will also update its ARP table based on the Request and add an entry for Middleman. So Gateway does not have to send an ARP Request to Middleman.


## ARP Annoucements

### Debian's Announcements

Now we start the Alf VM (Debian Linux 11) while having the ARP listener still running on Middleman (Kali Linux). We will observe an ARP announcement from Alf during its startup.

![Alf's ARP Announcements](/assets/img/01_middleman_alf_started_arp_announcement.png)

An ARP Annoucement looks like a regular ARP Request directed at the broadcast MAC address `FF:FF:FF:FF:FF:FF`, but the source ipv4 address (SPA) will be the same as the target ipv4 address (TPA). So SPA = TPA. Depending on the implementation the source and target MAC address might also be the same, but that is not required.

The other hosts in the network segment *can* use this Request to update their ARP table, but they can also choose to ignore it. Our Middleman Kali Linux chooses to ignore it. It does not add an entry for Alf in its ARP table based on the Annoucements.

```bash
$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.0.0.111               ether   08:00:27:cc:cc:cc   C                     eth0
# still only the Gateway
# no new entry for 10.0.0.1
```


Alf performs this Annoucement Request three times. Afterwards it performs a regular ARP Request to its configured Gateway (10.0.0.111).


We won't see the Reply from the Gateway because it will be a Unicast Ethernet frame directed directly at the source of the Request. Activating promiscuous mode on Middleman's network interface does not help here, because VirtualBox simulates a network switch between the three hosts. If the switch does its job correctly, then a unicast frame will not be sent to uninvolved hosts.

On Alf we can confirm that the ARP handshake was performed correctly even if we do not see it. The Gateway address pair will show up in Alf's ARP table.

![Alf's ARP Request to Gateway](/assets/img/02_middleman_alf_gateway_request.png)


### Windows 11's Annoucements

When we start Bert (Windows 11) we will also see ARP Announcements during startup. Windows 11 appears to play it safe and sends two different variants of the ARP announcement. 

![Bert's ARP Announcements](/assets/img/03_middleman_bert_arp_annoucement.png)

One kind has the SPA (IPv4 address) set to `0.0.0.0`. 

The second kind has `SPA = TPA` with both fields set to the interface ipv4 address (here `10.0.0.2`) just like Alf's Announcements.

Just like Alf, Bert will also send ARP requests to the configured gateway for its network interface as part of the setup during startup. 



## ARP Table Update Behavior

Like I mentioned before, not all implementations of ARP behave the same way when it comes to updating the ARP table.

The examples below assume the default configuration for the given OS on a fresh VM. Besides the default beavior you can influence the ARP update behavior (and you should do so in a hardened network environment) via configuration in almost all operating systems.

I hacked together an ARP sender using the code we already have used as a library:


```python
#!/usr/bin/env python3
# 0A75
# arp_sender.py
from arpfun import *

# ARP Sender
def main():
    while True:
        try:
            print(red("=" * 32))
            print(red("   Hacky Insecure ARP Sender"))
            print(red("=" * 32))
            print(green("[*] MAC format: ff-ff-ff-ff-ff-ff or ff:ff:ff:ff:ff:ff"))
            print(green("[*] IPv4 format: 255.255.255.255"))

            interface_name = input(blue4("[?] What interface do you want to use? (default: eth0) > ")) or "eth0"
            
            ethernet_local_mac = input(blue4("[?] ETHERNET Source MAC address? > "))
            ethernet_local_mac = ethernet_local_mac.replace(":", "-")
            ethernet_local_mac_raw = str_to_mac(ethernet_local_mac)

            ethernet_target_mac = input(blue4("[?] ETHERNET Target MAC address? > "))
            ethernet_target_mac = ethernet_target_mac.replace(":", "-")
            ethernet_target_mac_raw = str_to_mac(ethernet_target_mac)
            
            arp_local_mac = input(blue4(f"[?] ARP Sender MAC address? ({ethernet_local_mac}) [enter to confirm] > ")) or ethernet_local_mac
            arp_local_mac = arp_local_mac.replace(":", "-")
            arp_local_mac_raw = str_to_mac(arp_local_mac)

            arp_target_mac = input(blue4(f"[?] ARP Target MAC address? ({ethernet_target_mac}) [enter to confirm] > ")) or ethernet_target_mac
            arp_target_mac = arp_target_mac.replace(":", "-")
            arp_target_mac_raw = str_to_mac(arp_target_mac)

            arp_local_ip = input(blue4(f"[?] ARP Sender Ipv4 address? > "))
            arp_local_ip_raw = str_to_ipv4(arp_local_ip)

            arp_target_ip = input(blue4(f"[?] ARP Target Ipv4 address? > "))
            arp_target_ip_raw = str_to_ipv4(arp_target_ip)

            arp_operation = input(blue4("[?] ARP Operation? [1 = REQUEST; 2 = REPLY] > "))
            arp_operation_raw = int(arp_operation)

            arp_message = ARPMessage(
                0x1, 
                0x800, 
                0x6, 
                0x4, 
                arp_operation_raw, 
                arp_local_mac_raw, 
                arp_local_ip_raw,
                arp_target_mac_raw,
                arp_target_ip_raw
                )

            print(green("[*] ARP Message:"))
            print(arp_message)

            arp_raw = pack_arp_message(arp_message)
            
            ethernet_frame = EthernetFrame(
                ethernet_target_mac_raw, 
                ethernet_local_mac_raw,
                ETHER_TYPE_DICT_INVERS.get("ARP"),
                arp_raw
                )

            print(green(green("[*] Ethernet Header:")))
            print(ethernet_frame)

            ethernet_frame_raw = pack_ethernet_frame(ethernet_frame)

            confirm = input(blue4("[?] SEND? [ y ] > "))
            if confirm.startswith("y"):
                ETH_P_ALL = 3
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                sock.bind(( interface_name, 0 ))
                sock.send(ethernet_frame_raw)
                print(blue3("[+] Your frame has been sent!"))
            else:
                print(red("[-] Aborted!"))

            print("")

        except Exception as e:
            print("Error:", red(e))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReceived interrupt. Exiting...")

```

### Alf - Debian 11's Update Behavior

![Middleman's unsolicited ARP Reply](/assets/img/04_00_unsolicited_reply_toalf.png)

Alf will ignore unsolicited ARP Replies when it comes to updating its table. 

![Middleman's unsolicited ARP Reply](/assets/img/04_01_unsolicited_reply_toalf.png)

Alf (Debian) does not care for unsolicited Replies.

On the other hand, when we send a direct unicast ARP Request to Alf, then Alf will update its table and send a direct unicast Reply as expected. So an Ethernet broadcast is not required for the Request part of the handshake.

![Middleman updates Alf's table](/assets/img/05_direct_arp_toalf_update.png)

![Middleman updates Alf's table](/assets/img/05b_direct_arp_toalf_update.png)

We can also use this behavior to trick Alf into replacing existing entries like the one for the Gateway `10.0.0.111`:

![Middleman updates Alf's table](/assets/img/06_00_bamboozle_alf.png)

We can observe the MAC address for `10.0.0.111` being updated from the Gateway MAC address to the MAC address of Middleman:

![Middleman updates Alf's table](/assets/img/06_01_bamboozle_alf.png)


But Alf will quickly notice that this entry is bogus when our Middleman host does not actually respond to network traffic as expected: 

![Middleman updates Alf's table](/assets/img/06_02_bamboozle_alf.png)

If we want to spoof Alf permanently, then we will have to respond to its own ARP Requests and relay Ethernet traffic to the intended target (or make up appropriate responses).

But more about ARP spoofing in the next part of this series


### Bert - Windows 11's Update Behavior

Bert (Win11) also ignores unsolicited ARP Replies.

![Middleman unsolicited ARP Reply](/assets/img/07_00_unsolicited_reply_tobert.png)

![Middleman unsolicited ARP Reply](/assets/img/07_01_unsolicited_reply_tobert.png)


But updating Bert's ARP table with a Request also works the same way as with Alf.


![Middleman updates Bert's table](/assets/img/08_00_direct_arp_tobert_update.png)

![Middleman updates Bert's table](/assets/img/08_01_direct_arp_tobert_update.png)


Tricking Bert also works exactly the same way as with Alf:

![Middleman tricks Bert](/assets/img/09_00_bamboozle_bert.png)

Because Bert already knows Middleman, you will see two entries with the same MAC address:

![Middleman tricks Bert](/assets/img/09_01_bamboozle_bert.png)


Just like Alf, Bert will quickly notice that this entry is bogus though, if we do not keep up the charade. It will re-establish the correct entry for Gateway with ARP eventually.


### FreeBSD - pfSense Gateway

Unlike Windows 11 and Debian Linux, the pfsense Gateway will update its ARP table when you send an unsolicited ARP Reply.


## Reference: Commands for testing with ARP

**Note:** You will have to run most of these as root / Administrator.

### Linux:

```bash
# Print current ARP table
/usr/sbin/arp -n

# set interface to promiscuous mode
ip link set eth0 promisc on

# turn off automatic ARP for a given interface (this also clears ARP table)
# WARNING: this effectively makes it impossible for your host to communicate in the LAN until you turn it back on
ip link set dev eth0 arp off

# turn automatic ARP back on
ip link set dev eth0 arp on

# clear ARP table
ip -s -s neigh flush all
```

### Windows:

```bash
# Print current ARP table
arp -a

# Clear ARP table
arp -d

```

## arping

You can manually send ARP messages with the `arping` utility ([man page](https://www.man7.org/linux/man-pages/man8/arping.8.html)).

It can be used similarly to the regular `ping` to verify connectivity between two hosts, just on layer 2 rather than layer 3.


```bash
arping [-AbDfhqUV] [-c count] [-w deadline] [-i interval]
              [-s source] [-I interface] {destination}
```

You will have to run this command as root.

Noteworthy are the parameters:

```bash
-A
           The same as -U, but ARP REPLY packets used instead of ARP
           REQUEST.

-f
           Finish after the first reply confirming that target is alive

-U
           Unsolicited ARP mode to update neighbours ARP caches. No
           replies are expected.

-s source
           IP source address to use in ARP packets.
```

So the tool can also be used to manipulate ARP entries on other hosts. But this ability is somewhat limited. For example it won't allow you to pretend to be a different MAC Address (in the frame) than your interface default (without some hacking).