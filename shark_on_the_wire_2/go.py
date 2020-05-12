import json

flag = ""

with open("asdf.json", "r") as f:
  d = json.load(f)

ip_src = {}
ip_dst = {}

for p in d:
  # Not all packets have data, so use try and except to filter out the packets without data
  try:
    a = p["_source"]["layers"]["data"]["data.data"] # Get data
    src = p["_source"]["layers"]["ip"]["ip.src"] # Get src ips
    dst = p["_source"]["layers"]["ip"]["ip.dst"] # Get destination ips
  except KeyError:
    continue

  a = a.replace(":", "")
  s = str(bytes.fromhex(a), "ascii")

  # Take the src address and take the last part
  x = int(src.split('.')[-1])

  # See if the last part of the src ip is actually within the ascii range
  if 32 < x < 127:
    port = int(p["_source"]["layers"]["udp"]["udp.srcport"])
    if port > 5000:
      print(port)
      flag += chr(port - 5000)


print(flag)
print(flag.replace("a", ""))
