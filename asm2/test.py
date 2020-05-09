def asm2(arg1, arg2):
  # <+6>:   mov    eax,DWORD PTR [ebp+0xc]  ; 0xc is 12. So ebp + 12 points to arg2 if you use the diagram above to count
  # <+9>:   mov    DWORD PTR [ebp-0x4],eax  ; ebp - 4 is the local variable D
  d = arg2

  # <+12>:  mov    eax,DWORD PTR [ebp+0x8]
  # <+15>:  mov    DWORD PTR [ebp-0x8],eax
  c = arg1

  # <+18>:  jmp    0x50c <asm2+31>
  # <+20>:  add    DWORD PTR [ebp-0x4],0x1
  # <+24>:  add    DWORD PTR [ebp-0x8],0xaf
  # <+31>:  cmp    DWORD PTR [ebp-0x8],0xa3d3
  # <+38>:  jle    0x501 <asm2+20>
  while c <= 0xa3d3:
    d = (d + 1) & 0xffffffff # Apply a mask to truncate to 32 bits
    c = (c + 0xaf) & 0xffffffff # Apply a mask to truncate to 32 bits

  # <+40>:  mov    eax,DWORD PTR [ebp-0x4] ; eax is where the return value is usually in x86
  # <+43>:  leave
  # <+44>:  ret
  return d

print(hex(asm2(0xc,0x15)))
