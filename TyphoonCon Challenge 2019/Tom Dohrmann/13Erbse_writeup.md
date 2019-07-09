# Tom Dohrmann - Writeup

I used Ghidra for static analysis and x64dbg for dynamic analysis.

"Documentation of the attack flow being used to obtain the message":
After looking at the binary in Ghidra I quickly figured out that each packet has the following
format:
0-7: DEADBEEF
8: amount of appended data
9: byte inidicating the command
10 - \*: data packets

I was able to confirm this by writing a simple python script. If the packet doesn't follow the exact
format, the program throws an exception.

When I was looking at the main method in Ghidra I noticed that a bunch of buffers get setup (255 to
be exact).  The string I was supposed to extract was in the last buffer (index = 254). The commands
can be used to write data into the buffers like a ring buffer. However the ring buffer wraps around
before hitting 254, so I couldn't directly use that to obtain the data.

After tinkering around for a while I noticed that the program crashes if I sent it 128 3-commands
only containing two characters,  one 4-command packet and then 128 3-commands again. I got a
segfault accessing an invalid address (in my case it was 2). I suspected that it could be either the
address in the 3-command packets or the 4-command packet. So I changed the second dword in the
4-command packet to 0x62A000 and looked at the crash. The value got changed, but it got changed to
0x31500 which happens to be 0x62A000 divided by two and two also happens to be the value I sent for
the first dword in the packet. So I changed the first value to 4 (because I want to read 4 bytes)
and the second value to 0x62A7F0/4 and I got back the value contained at that address (figuring out
that I can just change the first value to 4 took me a LOOONG time, but eventually I figured it out).
So know I have a way allowing me to read 4 bytes at an arbitrary address. (I should note that after
each value read I need to close the connection and open a new connection, because frankly I couldn't
figure out how to properly reset the buffers and just opening a new connection works without any
problems)

Once I had that figured out the rest was pretty easy:
1. Read the value at 0x62A7F0 to get the address of the string in the heap
2. Read the string in four byte chunks
3. ???
4. Profit

[Exploit](4QcpLaPc.py)
