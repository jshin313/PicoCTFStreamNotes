d = bytearray(open("ctf.raw", "rb").read())

a = []

# Make 8 copies in a bytearray
for _ in range(8):
  a.append(bytearray(len(d)))


for i, byte in enumerate(d):
  for j in range(3):
    bit = ((byte >> j) & 1) # Extract a bit
    a[0][i] |= bit << (j + 5)

# for i in range(8):
#   with open("plane%i.raw" % i, "wb") as f:
#     f.write(a[i])
with open("output.raw", "wb") as f:
  f.write(a[0])
