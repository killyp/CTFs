<p style="text-align: left;"><img class="size-full wp-image-120 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/logo-1.png" alt="" width="600" height="284" /></p>
<p style="text-align: left;">"Old School Hack" was the one and only exploit focused problem of the Pragyan CTF.  As with every exploit problem, I first copy the binary, police_acedemy, to a Linux VM to run some initial commands on the binary.</p>
<p style="text-align: left;">File command to see what kind of executable we are working with.</p>
<p style="text-align: left;"><img class="size-full wp-image-121 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-3.jpg" alt="" width="1014" height="68" /></p>
<p style="text-align: left;">Checksec in gdb (peda) to see what kind of security features are enabled.</p>
<p style="text-align: left;"><img class="size-full wp-image-122 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-4.jpg" alt="" width="187" height="130" /></p>
<p style="text-align: left;">Strings command will print out all of the strings in the binary.</p>
<p style="text-align: left;"><img class="size-full wp-image-123 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Untitled.png" alt="" width="667" height="1093" /></p>
<p style="text-align: left;">So, I can see from these three commands that we have a 64-bit Linux executable that has Canaries and NX enabled.  We also get some serious hints from the strings command.  "flag.txt" (maybe with an H on the end) is probably the name of the file that has our flag inside it.  Looks like we will need to escalate our privileges in order to get the flag.  Probably with a password since we can clearly see a password prompt.  And finally, "kaiokenx20" looks like a great candidate for the password!</p>
<p style="text-align: left;">Let's run this binary (in an isolated VM) and see what it does!</p>
<p style="text-align: left;"><img class="size-full wp-image-124 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-5.jpg" alt="" width="338" height="45" /></p>
<p style="text-align: left;">Immediately we get a password prompt.  Let's try the likely candidate we found in the strings dump.</p>
<p style="text-align: left;"><img class="size-full wp-image-125 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-6.jpg" alt="" width="424" height="208" /></p>
<p style="text-align: left;">Sweet, that was easy! Enter 7 to print the flag!</p>
<p style="text-align: left;"><img class="wp-image-126 size-full aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-7-e1520258900127.jpg" alt="" width="531" height="235" /></p>
<p style="text-align: left;">Uh-oh.... Looks like this one is going to be harder than I thought.  Let's open it up in IDA (or your favorite disassembler) and take a look to see what is happening.</p>
<p style="text-align: left;"><img class="size-full wp-image-127 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture.png" alt="" width="1253" height="846" /></p>
<p style="text-align: left;">From this top section of the main function we can tell a few things and get some serious hints on what we need to do.  First of all, we have a scanf with the string format (%s) as an argument.  This scanf is what prompts us for the password.  We were also right about what the password was as we can see a strncmp call that compares our input text with the string "kaiokenx20".  But wait... That is a strncmp() not strcmp().  You can read the man pages about it <a href="https://linux.die.net/man/3/strncmp">here</a> but the main difference is that strncmp takes a size_t as a third argument and only compares that number of characters between the two strings.  We can also see that the size it takes is 0x0A which is 10 in decimal.  This is a major clue as it means we can pass in whatever size string we want into the scanf and as long as the first 10 bytes match our password it will succeed.  This means we can probably perform a buffer overflow here but remember that Canaries and NX are enabled so taking control of the $RIP might not be that easy.  Let's take a look at the next section of code.</p>
<p style="text-align: left;"><img class="size-full wp-image-129 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-1.png" alt="" width="1063" height="650" /></p>
<p style="text-align: left;">There isn't really anything special here.  We can tell that our selection of which "Case Number" to view is handled with a switch case statement, so let's look at them.</p>
<p style="text-align: left;"><img class="size-full wp-image-130 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-2.png" alt="" width="1216" height="271" /></p>
<p style="text-align: left;">I couldn't get a screenshot of all the switch case statements so just trust me when I say that cases 1-5 looked almost identical to case 6 in the picture above.  We can see why it didn't work when we ran the program earlier and entered the correct password.  Case 7 puts what looks like an ASCII string into Var_30 then prints our we don't have required privileges and then exits.  If we convert the hex to ASCII it is txt.galf which is flag.txt backward, the string we saw in the strings dump.  Also if we look at Case 6, Var_30 is being loaded with a much longer ASCII string.  Turns out it is a .dat filename which means Var_30 is probably being used as a variable to hold filenames.</p>
<p style="text-align: left;"><img class="size-full wp-image-131 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-3.png" alt="" width="837" height="709" /></p>
<p style="text-align: left;">This next section of code looks to be where the print_record function is called with a paramter of Var_30 (pointer to filename) and then cleanup before the program exits.  If print_record returns a -1 in decimal it will print "No such record exists."  Also if you look at the previous three screenshots you can see that the green arrow is the default case for the switch case statement.  In this path of the program Var_30 is never changed.  This means we can overwrite the stack with the scanf vuln we found and put the name of the file into Var_30.  Then when the default case is called Var_30 keeps the value we gave it all the way through to the print_record function call!</p>
<p style="text-align: left;">It looks like print_record function takes a pointer to s string as it's argument but let's take a look at it in IDA also to make sure.</p>
<p style="text-align: left;"><img class="size-full wp-image-134 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-5.png" alt="" width="975" height="770" /></p>
<p style="text-align: left;">Yep, just like I thought, the print_record takes a pointer to a filename and the opens it.  But very strangely, it checks to see if the filename is 0x24 characters in length.  Since our filename, "flag.txt" is only 0x08 characters long it will not pass this check and will exit with a return of -1.  We can fix this though by adding a padding to our file name of reapeating "./" since this is synonymous with current directory.  So to get to 0x24 characters, our filename will be:</p>

<blockquote>././././././././././././././flag.txt</blockquote>
<p style="text-align: left;">So let's run the program in gdb to figure out the size of padding needed on the stack between the password and filename variables.</p>


[code]
gdb police_acedmy       // Start gdb
b *0x4009e6             // Set Breakpoint after scanf call for password
run
kaiokenx20AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK
x/s $rbp-0x30           // The locoation of Var_30 which is our filename
[/code]

<p style="text-align: left;">This will return:</p>

<blockquote>0x7fffffffdcc0: "BBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK"</blockquote>
<p style="text-align: left;">So we know the needed buffer between the password is "AAAABB" or 6 bytes. So let's write our exploit! The payload of our exploit will be constructed "password + padding + filename".</p>


[python]python -c 'print("kaiokenx20"+"AAAABB"+"././././././././././././././flag.txt")' | nc 128.199.224.175 13000[/python]

<p style="text-align: left;">Since this payload of this exploit is all ASCII we can also use the echo command to pipe in our input.</p>


[bash]echo "kaiokenx20AAAABB././././././././././././././flag.txt" | nc 128.199.224.175 13000[/bash]

<p style="text-align: left;"><img class="size-full wp-image-135 aligncenter" src="https://killyp.com/wp-content/uploads/2018/03/Capture-6.png" alt="" width="913" height="339" /></p>
<p style="text-align: left;">Success!!!</p>
<p style="text-align: left;"></p>
