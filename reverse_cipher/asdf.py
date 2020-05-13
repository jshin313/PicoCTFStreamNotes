d = bytearray(open("rev_this", "rb").read())

for i in range(8, 23):
  if i % 2 == 0:
    d[i] -= 5
  else:
    d[i] += 2

print(d)