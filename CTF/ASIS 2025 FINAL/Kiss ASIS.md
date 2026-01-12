# Write-up: Kiss ASIS Crypto

## 1. Challenge Overview

We are provided with a Python script running on a server. The server performs the following actions:

1. **Generates a Key Pair:** It uses a custom RSA-like key generation algorithm involving a random parameter $k$ (between 1 and 6) and a large modulus $N$ (1024 bits).
    
2. **Encrypts a Secret:** It generates a random string, encrypts it using the generated public key $(N, e)$, and provides the ciphertext.
    
3. **Challenge:** The user must decrypt the random string and send it back to the server to verify ownership of the private key. If successful, the server releases the flag.
    

## 2. Vulnerability Analysis

The core weakness lies in the `genkey` function, specifically how the public exponent $e$ is derived.

### The Code

Python

```
p, q = [getPrime(nbit >> 1) for _ in ':)']
N = p * q
phi = (p ** k - 1) * (q ** k - 1)    # <--- Non-standard Phi
d = getPrime(dbit)                   # d is approx 1024 bits
e = inverse(phi + (-1)**r * d, phi)  # <--- Vulnerable construction
```

### The Math

In standard RSA, 1$e$ is usually small (e.g., 65537) and chosen first.2 Here, $e$ is calculated after $d$ and $\Phi$ are chosen, using this modular inverse relation:

$$e \equiv (\Phi \pm d)^{-1} \pmod \Phi$$

This implies:

$$e \cdot (\Phi \pm d) \equiv 1 \pmod \Phi$$

We can rewrite this congruence as an equality by introducing an integer $m$ (the quotient):

$$e(\Phi \pm d) = m \cdot \Phi + 1$$

Rearranging the terms:

$$e(\pm d) = (m - e)\Phi + 1$$

Let $X = e - m$. Since $e \approx \Phi$ (because $d$ is small relative to $\Phi$), $X$ will be small.

$$e \cdot d = X \cdot \Phi \mp 1$$

This equation looks strikingly similar to the RSA key equation $ed = k\phi(N) + 1$, which is susceptible to **Wiener's Attack** when $d$ is small.

## 3. Deriving the Attack

The goal is to recover $d$. We know $e$ and $N$. We do not know $\Phi$, but we can approximate it.

### The Approximation

Since $N = pq$, and $p, q \approx \sqrt{N}$, the custom $\Phi$ can be approximated as:

$$\Phi = (p^k - 1)(q^k - 1) \approx p^k q^k = (pq)^k = N^k$$

Now we substitute $\Phi \approx N^k$ into our key equation:

$$e \cdot d \approx X \cdot N^k$$

Dividing both sides by $d \cdot N^k$:

$$\frac{e}{N^k} \approx \frac{X}{d}$$

### Legendre's Theorem (Continued Fractions)

Legendre's Theorem states that if a rational number $\frac{P}{Q}$ approximates a real number $\alpha$ such that:

$$\left| \alpha - \frac{P}{Q} \right| < \frac{1}{2Q^2}$$

Then $\frac{P}{Q}$ is necessarily one of the convergents of the continued fraction expansion of $\alpha$.

In our case:

- $\alpha = \frac{e}{N^k}$ (Known values)
    
- $\frac{P}{Q} = \frac{X}{d}$ (Unknown target)
    

We can recover $d$ by computing the continued fraction of $\frac{e}{N^k}$ if the approximation error is small enough.

### Why do we need $k \ge 4$?

The approximation error comes from the difference between $\Phi$ and $N^k$.

$$\Phi \approx N^k - (p^k + q^k) \approx N^k - 2N^{k/2}$$

The relative error is roughly $\frac{1}{N^{k/2}}$.

For Legendre's theorem to hold, we need the error to be smaller than $\frac{1}{2d^2}$.

Since $d \approx N$ (1024 bits), we need:

$$\frac{1}{N^{k/2}} < \frac{1}{2N^2}$$

$$N^{k/2} > 2N^2 \implies \frac{k}{2} > 2 \implies k > 4$$

- **If $k=1, 2, 3$:** The approximation is too loose; the attack fails.
    
- **If $k=4$:** Borderline, but often works.
    
- **If $k=5, 6$:** The approximation is extremely precise; the attack works instantly.
    

## 4. Exploitation Steps

1. **Connect** to the service.
    
2. **Retrieve Public Key:** Get $N$ and $e$.
    
3. **Detect $k$:** Calculate the bit length of $e$. Since $e \approx \Phi \approx N^k$, the bit length of $e$ will be roughly $k$ times the bit length of $N$.
    
    - If $k < 4$, restart the connection.
        
    - If $k \ge 4$, proceed.
        
4. **Recover $d$:**
    
    - Compute $N^k$.
        
    - Calculate the continued fraction convergents of the fraction $\frac{e}{N^k}$.
        
    - The denominators of these convergents are candidates for $d$.
        
5. **Decrypt:** Test each candidate $d$ by attempting to decrypt the ciphertext. If the result is a readable ASCII string, we have found the correct key.
    
6. **Get Flag:** Send the decrypted string to the server.
    

## 5. Solution Script

Here is the complete Python script to automate the attack.

Python

```
#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import long_to_bytes
import sys

# Challenge connection details
HOST = '65.109.214.93'
PORT = 13137

context.log_level = 'info'

def get_convergents(e, n_k):
    """
    Generator for continued fraction convergents of e / n_k
    Yields pairs (numerator, denominator) corresponding to (X, d)
    """
    cf = []
    num, den = e, n_k
    
    # Generate continued fraction coefficients
    for _ in range(2000):
        if den == 0: break
        a = num // den
        cf.append(a)
        num, den = den, num % den

    # compute convergents
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    
    for a in cf:
        p2 = a * p1 + p0
        q2 = a * q1 + q0
        yield p2, q2
        p0, p1 = p1, p2
        q0, q1 = q1, q2

def solve():
    while True:
        try:
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b'[Q]uit')
            
            # 1. Get Public Parameters
            r.sendline(b'p')
            r.recvuntil(b'N = ')
            N = int(r.recvline().strip())
            r.recvuntil(b'e = ')
            e = int(r.recvline().strip())
            
            # 2. Get Encrypted Message
            r.recvuntil(b'[Q]uit')
            r.sendline(b'e')
            r.recvuntil(b'enc = ')
            c = int(r.recvline().strip())

            # 3. Estimate k based on bit lengths
            n_len = N.bit_length()
            e_len = e.bit_length()
            k = round(e_len / n_len)
            
            log.info(f"Checking instance: N={n_len} bits, estimated k={k}")

            if k < 4:
                log.warning("k is too small. Retrying for a vulnerable instance...")
                r.close()
                continue
            
            log.success(f"Vulnerable k={k} found! Attacking...")

            # 4. Wiener's Variant Attack
            Nk = pow(N, k)
            found = False
            
            for _, d in get_convergents(e, Nk):
                # Optimization: d must be roughly 1024 bits
                if d.bit_length() < 500: continue
                if d.bit_length() > n_len + 50: break 

                try:
                    # Attempt Decryption
                    m_cand = pow(c, d, N)
                    msg_bytes = long_to_bytes(m_cand)
                    
                    # Validate if message is printable ASCII (as per challenge source)
                    if 14 <= len(msg_bytes) <= 40 and all(32 <= b <= 126 for b in msg_bytes):
                        log.success(f"Secret Recovered: {msg_bytes}")
                        
                        # 5. Submit Secret
                        r.recvuntil(b'[Q]uit')
                        r.sendline(b's')
                        r.recvuntil(b'secret message: ')
                        r.sendline(msg_bytes)
                        
                        # 6. Print Flag
                        response = r.recvall(timeout=2).decode()
                        if "ASIS{" in response:
                            print("\n" + "="*40)
                            print(re.search(r'ASIS\{.*?\}', response).group(0))
                            print("="*40 + "\n")
                            found = True
                            break
                except Exception:
                    pass

            if found:
                r.close()
                break
            else:
                r.close()

        except Exception as e:
            log.error(str(e))
            if 'r' in locals(): r.close()

if __name__ == "__main__":
    solve()
```