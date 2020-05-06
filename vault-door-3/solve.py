password = bytearray([x for x in range(32)]) # Generates an array with numbers from 0 to 31
buffer = bytearray(32)

s = bytearray("jU5t_a_sna_3lpm13gc49_u_4_m0rf41")

# This gets the correct order of indexes to descramble s
for i in xrange(0, 8):
    buffer[i] = password[i]
for i in xrange(8, 16):
    buffer[i] = password[23-i]
for i in xrange(16, 32, 2):
    buffer[i] = password[46-i]
for i in xrange(31, 15, -2):
    buffer[i] = password[i]

print str(buffer).encode("hex") # Now we have the indexes in buffer

p = bytearray(32)

for i, idx in enumerate(buffer):
  p[i] = s[idx] # Put all the letters in the right order

print p
