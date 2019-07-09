# Niklas Beritfeld - Writeup

after reversing the binary i found out that the Thread ID which each accepted
connection uses is only stored in a byte, while the server sockets listens for
300 connections. This initally gives an attacker roughly 45 tcp connections
which collide with each other.  This collion can be abused in the internal
storage structure and can be used to obtain an arbitrary read.  After a request
was parsed and its method aplied the resulting vector of data is stored into a
storage buffer which is dependent on its Thread ID.  What is more is that when
two connection collide with each other it is possible to change the type of the
message in this very internal buffer.  The data from the first request is still
stored along with the current array size. The second request notices the size
but not the type, storing its data after the first but also changing the type.
As a result this turns into a Type collion and grants an attacker a leak for
heap pointers and also arbitrary read access.

Some notes on my provided exploit: i have tested this on win7 aswell as win10
on 3 different machines.  It isnt as targeted as i wanted it to be, but should
still print the message (im dumping the heap until the message has been
retrieved) Only works if it can get all 300 connections, but should be possible
with less (check when another socket gets data sent by another) i havent
implemented this

[Exploit](exp.py)
