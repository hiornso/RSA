# RSA

Development of a program to do RSA key generation, encryption and decryption, to teach myself how this stuff works. Please don't actually use this, I can't make any guarantees about whether or not it's secure - I'm doing this to *learn* about RSA.

The C version is SO much faster and better and cooler in every way :)
It uses GMP so that is a requirement for compilation and is also why it is so fast

Stuff implemented:

Key generation:
    Multithreaded random number generation and checking to find large prime numbers
    Use of the Extended Euclidean Algorithm to find the private exponent (I did this myself when I was first trying this stuff out in python but now I'm using GMP in C so it makes more sense to use the built-in GMP EEA function since it's faster)

Encryption/Decryption:
    Padding bytes to increase security by removing possible patterns in messages


Overview of how program works:

Keygen:
-generate 2 primes, p and q
-find n = p * q
-find v = (p - 1) * (q - 1)
-choose e to be coprime to v, normally 65537 = 2^16+1 by default (very small e, for example 3, reduced security if the later powmods don't actually change the message so we choose a big power to be on the safe side)
-find d such that e * d == 1 (mod v): this is done by using the extended euclidean algorithm to solve d*e + k*v = 1 (we can guarantee this to be 1 since we chose e to be coprime to v so that gcd(e,v)==1) then taking d = d%v which will give us a d which is both positive and a valid solution to the above equation (I dislike this implementation of modulo where everything is rounded towards -inf, and it seems most people agree: x86, arm, RISC-V and generic C all use truncating division and mod by default. It does, though, give us a quick way to find the solution we want)
-output the public key (e,n) and private key (d,n) to files

Encryption:
-encode the message as a series of integers (I refer to each integer as a "chunk" of the message)
-add random padding bytes. This is to increase security by removing patterns from the message that may still be visible after encryption.
-The chunk must now be smaller than n
-find m^e mod n where m is the message chunk as an integer and e,n are the public key

Decryption:
-find m^d mod n where m is the encrypted message chunk (an integer) and d,n are the private key
-strip the random padding bytes
-convert the integer back to a series of characters
-there is some extra work to know how much of the final chunk was actual message, since if the original message was not an exact multiple in size of the max chunk size (for usable data, not including padding) then the final chunk will not be 100% message data- more random data will have been inserted

Usage:
C:
Compile using gcc -o crypt crypt.c -lgmp -lpthread
Use as
./crypt --keygen
./crypt --encrypt --infile file.txt
./crypt --decrypt --infile encrypted.txt
More options shown in the source

Python:
Run in the python environment
public,private = rsa_keygen(nBits=2048) # nBits=2048 will take ages but result in a secure 4096-bit key. 512 bits is the default, for
                                        # demonstration purposes
enc = encrypt("test message",public) # can also specify paddingBytes=, this defaults to 16
dec = decrypt(enc,private)  # dec should now be "test message" - NB if you used a non-default number for paddingBytes while encrypting you must
                            # specify the same number while decrypting using paddingBytes=