[bits 32] ; 32 bit since esp instead of rsp
asm1:
push   0x529
push   0x41414141
push   ebp
mov    ebp,esp
cmp    DWORD [ebp+0x8],0x767
jg     asm1+37+10
cmp    DWORD [ebp+0x8],0x1f3
jne    asm1+29+10
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
jmp    asm1+60+10
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60+10
cmp    DWORD [ebp+0x8],0xcde
jne    asm1+54+10
mov    eax,DWORD [ebp+0x8]
sub    eax,0xb
jmp    asm1+60+10
mov    eax,DWORD [ebp+0x8]
add    eax,0xb
pop    ebp
ret