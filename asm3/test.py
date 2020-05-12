from struct import pack, unpack # For converting stuff to little endian

""" Just converts to little endian"""
def dd(v):
  return pack("<I", v)

""" Read word: Returns unsigned integer 16 bits from little endian"""
def rw(d):
  return unpack("<H", d)[0]

# set up the stack before the asm3 function is called
stack = bytearray(dd(0) + dd(0) + dd(0xc264bd5c) + dd(0xb5a06caa) + dd(0xad761175)) # dd(0) are there for saved ebp and return address

# eax is split into different parts
# [    eax    ] ; 4 bytes
# [   ] [ ax  ] ; ax is 2 bytes
# [  ] [ah][al] ; ah and al are both only 1 byte

# <+5>:   mov    ah,BYTE PTR [ebp+0x9]
ax = stack[9] << 8 # grab byte at index 9 and shift left by a byte since ah is the second lowest byte

# <+8>:   shl    ax,0x10
ax = ((ax & 0xffff) << 0x10) & 0xffff # First grab only 2 bytes from ax and shift left by 0x10 and then only grab 2 bytes of the result

# <+12>:  sub    al,BYTE PTR [ebp+0xd]
al = ((ax & 0xff) - stack[0xd]) & 0Xff # Grab bottom byte of ax and subtract the byte at index 0xd. then grab only bottom byte of that
ax = (ax & 0xff00) | al # Zero out bottom bytes of ax and then fill bottom byte of ax with al, leaving top byte of ax unchanged

# <+15>:  add    ah,BYTE PTR [ebp+0xf]
ah = (((ax >> 8) & 0xff) + stack[0xf]) & 0xff # Take top byte from ax and add byte at index 0xf. Then get only lowest byte from it since ah is only 16 bits
ax = (ax & 0x00ff) | (ah << 8) # Transfer ah to ax by zeroing out top byte of ax and leaving bottom byte of ax unmodified 

# <+18>:  xor    ax,WORD PTR [ebp+0x10]
ax ^= rw(stack[0x10:0x12])

print("0x%.4x" % ax)