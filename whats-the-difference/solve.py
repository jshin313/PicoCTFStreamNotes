d = open("kitters.jpg", "rb").read() # Unmodified file
e = open("cattos.jpg", "rb").read() # modified file

f = ""

# Zip takes one element from d and one from e for every iteration
for a, b in zip(d, e):
  if a != b:
    f+=b

print f