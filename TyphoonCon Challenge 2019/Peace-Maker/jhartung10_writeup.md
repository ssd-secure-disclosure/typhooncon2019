# Peace-Maker - Writeup

The attached script achieves that by dumping 0x3000 bytes of the heap around the area where the
hidden message buffer is expected. I'm abusing two bugs in the binary:

1. The per-thread vector that stores all responses to send back to the client isn't cleared between
requests. So the next request could use a different command ID, but pack the responses of the
previous commands the way the current command is packed.  Commands 2 (to upper case) and 3 (to lower
case) copy the sent message into one of the buffers allocated in the global array of char\*.  The
pointer to that buffer is then put into a structure together with the length of the string and saved
in a thread-local vector to send back to the client. Command 4 does some math on two dwords sent to
it and stores it in the same fields of the structure in the thread-local vector. By sending command
2 first and command 4 afterwards, command 4 returns the heap address of the buffer put into the
vector in command 2. Same works the other way around.  Crafting a special message in command 4 can
put an arbitrary pointer in the vector which is printed out by command 2.

2. The length of the buffer to return in responses to messages of command 2/3 isn't truncated to 1
byte, but the whole 4 bytes of the structure are used as the length. So you can return way larger
strings than just 0xff by putting a larger number as the length using command 4.

I'm dumping the addresses of all accessible heap buffers and proceed to dump 0x3000 bytes around the
second to largest heap address chunk. Then see if the "TyphoonCon" string was somewhere in there and
print it.  There are more comments in the code.

```
$ python heapdump.py
[+] Opening connection to 10.0.2.2 on port 13337: Done
[*] Putting heap addresses of buffers into the vector.
[*] Received 253 strings for command 2
[*] Leak the addresses.
[*] Received 254 messages for command 4
[!] Response truncated! 1420 < 2038
[*] Closed connection to 10.0.2.2 port 13337
[+] Opening connection to 10.0.2.2 on port 13337: Done
[*] Dumping heap 0xeb4000 - 0xebe000 (a000 bytes)
[*] Received 12 messages for command 4
[*] Received 13 strings for command 2
[+] Found target string: TyphoonCon 2019 Get this string first!
[*] Closed connection to 10.0.2.2 port 13337
```

[Exploit](heapdump.py)
