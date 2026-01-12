# Cryptic Grid Revenge - ASIS CTF Writeup

## Challenge Info

- **Category:** Crypto
- **Server:** `65.109.210.233:11113`

## Overview

A server exposes an AES-ECB encrypted grid mapping. We need to recover the original `core` permutation (64 values shuffled from 0-63).

## Source Code Analysis

```python
core = list(range(0x40))
shuffle(core)
core = bytes(core)

grid = {wrap(i): wrap(core[i]) for i in range(0x40)}
```

The grid maps `AES_ECB(index)` → `AES_ECB(core[index])`.

### Available Commands

| Command | Cost | Description |
|---------|------|-------------|
| **Q** (Query) | 1 attempt | Submit `entry` + `delta`, server computes `idx = (AES_decrypt(entry) + delta + 0x20) & 0x3F` |
| **R** (Reflect) | 21 attempts | Encrypt or decrypt based on input length |
| **C** (Check) | - | Submit final core mapping |

### Query Behavior

```python
idx = (wrap(entry, False) + delta + 0x20) & 0x3F
out = grid[wrap(idx)]
if wrap(out, False) == focus:
    pr(f"ALIGNMENT FOUND at {idx}")
    attempts = MAX_ATTEMPTS      # Reset to 42
    grid = build_grid(core)      # New AES key, SAME core!
    focus = (focus * 5 + 3) & 0x3F
```

## Vulnerability

Two critical observations:

1. **Core persists across rounds** - Only the AES key changes, the underlying `core` permutation stays identical
2. **Deterministic focus sequence** - Next focus is always `(focus * 5 + 3) % 64`

This means we can map one `core[idx] = focus` per round and accumulate knowledge across all rounds.

## Attack Strategy

1. For each round, brute-force all 64 possible deltas (-32 to +31)
2. When "ALIGNMENT FOUND at X" appears, record `core[X] = current_focus`
3. Repeat for 64 rounds until full mapping is recovered
4. Submit with command C

## Solve Script

```python
#!/usr/bin/env python3
from pwn import *
import re
import time

context.log_level = 'info'

def solve():
    while True:
        core = [None] * 64
        try:
            r = remote('65.109.210.233', 11113)
            r.recvuntil(b'e[X]it')
            time.sleep(0.3)
            
            while None in core:
                r.sendline(b's')
                time.sleep(0.2)
                menu = r.recvuntil(b'e[X]it', timeout=10).decode()
                
                m = re.search(r'Attempts: (\d+).*?Focus pulse: (\d+)', menu, re.DOTALL)
                if not m: break
                
                attempts, focus = int(m.group(1)), int(m.group(2))
                known = 64 - core.count(None)
                log.info(f'Focus: {focus} | Known: {known}/64')
                
                for delta in range(-32, 32):
                    time.sleep(0.1)
                    r.sendline(b'q')
                    r.recvuntil(b'Entry (hex):')
                    r.sendline(b'00' * 16)
                    r.recvuntil(b'Delta:')
                    r.sendline(str(delta).encode())
                    
                    resp = r.recvuntil(b'e[X]it', timeout=10).decode()
                    
                    if 'ALIGNMENT' in resp:
                        idx = int(re.search(r'at (\d+)', resp).group(1))
                        if core[idx] is None:
                            core[idx] = focus
                            log.success(f'core[{idx}] = {focus}')
                        break
            
            if None not in core:
                log.success('Submitting solution...')
                r.sendline(b'c')
                r.recvuntil(b'Core key:')
                r.sendline(bytes(core).hex().encode())
                print(r.recvall(timeout=5).decode())
                return
                
            r.close()
        except Exception as e:
            log.warning(f"Error: {e}")
            try: r.close()
            except: pass
            time.sleep(2)

if __name__ == '__main__':
    solve()
```

## Key Insights

- The AES encryption is a red herring - we don't need to break it
- The oracle leaks one mapping per round via the ALIGNMENT response
- Connection stability is crucial - timeouts and sleeps prevent server overload

## Flag

```
ASIS{cr1pt1c_gr1d_r3v3ng3_m4st3r}
```
