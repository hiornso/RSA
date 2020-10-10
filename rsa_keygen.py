from random import getrandbits
from time import time

def ApowBmodC(x,n,c): # returns a^b (mod c), or in python, a**b % c
    # uses repeated squaring, based on algo from
    # https://en.wikipedia.org/wiki/Exponentiation_by_squaring
    # but not hard to understand:
    # a **4 can be broken down into (a**2)**2
    # and for odd powers, we multiply by one extra (total stored in y)
    # this is the same as the builtin pow(x,n,c)
    y = 1
    while n > 0:
        if n % 2:
            y = (x * y) % c
        x = (x * x) % c
        n >>= 1
    return y % c

def isLargePrime(w,iterations):
    # test if prime based on Miller-Rabin Primality test,
    # written referencing FIPS standard thing that defines
    # how one is supposed to do this
    a = 0
    m = w - 1
    while m % 2 == 0:
        m //= 2
        a += 1
    
    wlen = len(bin(w)) - 2 # python bin() returns a string starting "0b"

    for i in range(iterations):
        b = getrandbits(wlen) | 1 # no primes are even (we are not interested in 2)
        while b <= 1 or b >= w - 1:
            b = getrandbits(wlen) | 1
        z = ApowBmodC(b,m,w)
        if z == 1 or z == w - 1:
            continue
        brokeEarly = False
        for j in range(a):
            z = ApowBmodC(z,2,w)
            if z == w - 1:
                brokeEarly = True
                break
            if z == 1:
                return False # not a prime
        if brokeEarly:
            continue
        return False
    return True # almost certainly prime, given a fair no. of iterations

def generateRandomPrime(nBits = 1024, iterations = 64):
    while not isLargePrime(n := getrandbits(nBits),iterations):pass
    return n

def EEA_dfinder(a,b):
    r = [a,b]
    s = [1,0]
    t = [0,1]
    q = []
    while r[-1] != 0:
        q.append(r[-2] // r[-1])
        r.append(r[-2] - q[-1] * r[-1])
        s.append(s[-2] - q[-1] * s[-1])
        t.append(t[-2] - q[-1] * t[-1])
    return [s[-2],t[-2]]

def pos_dfinder(a,b):
    x,y = EEA_dfinder(a,b)
    if x > 0:
        return x
    m = x // b # (x-u)/b
    return x - m * b # x - ((x-u)/b)*b = x - x + u = u

def rsa_keygen(p = None, q = None, nBits = 512):
    print("WARNING: If primes were not specified, random ones will be generated\
 - these could be very big if nBits was set to a large number, and so since python\
 is rather slow, the function may take a few minutes to run. This is certainly the \
 case for 2048 bits, which takes ~45 seconds for each prime (2048 bits is the recommended\
  minimum as of 2020). The default is 512 bits, which is fast but not that secure.")
    # no. of bits according to FIPS should be 2048
    if p == None:
        start = time()
        p = generateRandomPrime(nBits)
        print("Generated prime (p) in %f seconds"%(time()-start))

    if q == None:
        start = time()
        q = generateRandomPrime(nBits)
        print("Generated prime (q) in %f seconds"%(time()-start))


    n = p * q
    v = (p - 1) * (q - 1)

    k = 2**16+1
    while v % k == 0: # while not coprime
        k += 2
    # ERROR: THE ABOVE DOES NOT GUARANTEE COPRIME

    # solve dk + fv = 1 for d,f ints, find smallest positive d
    d = pos_dfinder(k,v)
    
    public  = (k,n)
    private = (d,n)

    return (public,private)

def paddedHex(c):
    r = hex(ord(c))[2:]
    if len(r)<2:
        r = '0'+r
    return r

def encrypt(messageAsString,publicKey,paddingBytes = 16):
    k,n = publicKey
    M = messageAsString
    nbits = len(bin(n)) - 3 # any chunk of message should be fewer bits than this
    nchars = nbits//8 - paddingBytes
    if nchars < 1:
        print("The key is too small to encode a message with the specified number\
 of padding bytes, so the padding is being removed. Be warned, this will make the\
 chiper even less secure and more susceptible to being guessed using cribs, but\
 then again if you're using such a stupidly small key you obviously don't care\
aabout security anyway. Also, remember to use paddingBytes=0 when \"decrypting\"")
        nchars = nbits//8
        paddingBytes = 0
    msg_chunks = []
    while M:
        msg_chunks.append(M[:nchars])
        M = M[nchars:]
    # we add random padding bits to make it nearly impossible to use cribs/repetitions in the message to guess the message contents
    msg_chunks = [int(''.join([paddedHex(j)for j in i]+[hex(getrandbits(4))[2:]for j in range(paddingBytes*2)]),16) for i in msg_chunks]
    return [ApowBmodC(m,k,n)for m in msg_chunks]

def decrypt(ciphertext,privateKey,paddingBytes = 16):
    d,n = privateKey
    M = ciphertext
    msg_chunks = [ApowBmodC(m,d,n)for m in M]
    msg = ''
    for m in msg_chunks:
        if paddingBytes != 0:
            h = hex(m)[2:-paddingBytes*2]
        else:
            h = hex(m)[2:]
        if len(h)%2:
            h = '0' + h
        chrs = []
        while h:
            chrs.append(chr(int(h[:2],16)))
            h = h[2:]
        msg += ''.join(chrs)
    return msg
