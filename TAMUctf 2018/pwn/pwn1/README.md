# pwn1 - Solution

This is the first problem in the pwn section of the TAMU 2018 CTF competition.  In the pwn section the solution usually involves exploiting a vulnerability in the binary to find the flag.  So to start this problem lets open the binary up in IDAPro and take a look to see if we can find anything useful.

![IDA](http://killyp.com/wp-content/uploads/2018/02/Capture-1.jpg)

So in the disassembly we can see a compare of var_C to 0xF007BA11.  Then if these two are equal the print_flag function is called.  The only problem is that var_C is never edited. It is initialized to zero and then never changed.  But lucky us, there is a gets call right there that we can overwrite the variable with by overflowing the stack! So lets run this binary in gdb and see what it would take to overwrite this var_C variable on the stack. NOTE:  Always remember to never run binaries on your system you don't absolutely trust. Even though these binaries are from TAMU I would recommend having a spare VM to run CTF binaries in so if the system gets corrupted you can just restore the VM to a previous point.

So we will set a breakpoint at 0x0804861A (the command right after the gets call) so we can look at the stack. Then run the program.
```bash
start
b *0x0804861A
run
```
Then it will prompt us for the 'secret'.  We want to give it a substantial amount of text. Usually I like to do a pattern such as:

AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMOOOOPPPP

That will probably be more than enough. Now lets examine the stack.

![gdb](http://killyp.com/wp-content/uploads/2018/02/Capture-2.jpg)

The x/32x $ESP command will print out the $ESP register followed by $ESP+4, then $ESP+8, then $ESP+12, etc.  Then I do a x/x $EBP command to see where the $EBP is pointing and as you can see the saved $EBP from the last stack frame has been overwritten with "IJJJ". We also know that the variable, var_0C, is being stored at $EBP - 0Ch.  To overwrite the variable, var_0Ch, we need to find the distance from where our text starts being stored to where Var_0C is on the stack.  We know that Var_0C is $EBP - 0x0C so the location of Var_0C is (0xffffcf08 - 0x0C).  So the address that we need to be equal to 0xF007BA11 is located at 0xffffcefc. We can also see in the image above that our text is getting saved on the stack starting at address 0xffffcee5.  The distance from this address to the address of Var_0Ch is then 0x17 which is 23 in decimal.  So let's put 23 A's into stdin and then the text we need there, which is 0xF007BA11.  Remember that x86 is Little Endian so it will need to go into stdin as 0x11 0xBA 0x07 0xF0.  These characters cannot be represented with ASCII so we will use python to help us with piping in the binary.

```bash
python -c 'print("A"*17 + "\x11\xBA\x07\xF0")' | ./pwn1
```
Which yields the result...

![pwn1](http://killyp.com/wp-content/uploads/2018/02/Capture-3.jpg)

Success!!! We have the key!

We could have also solved this problem with just static analysis of the disassembled code in IDAPro.  Using our knowledge of where things are stored on the stack in x86 we could have calculated the size needed for our overflow.
