ABSTRACT

Do not use this library in your uranium enrichment facility.

TL;DR

I am not an expert in cryptology. This project was started to make adding
cryptography to another network-capable project easy and to be reused in
future projects. I did my best to avoid any weaknesses I could find information
about and documented why I did certain things the way I did in the source code.
In the end, this means nothing. It could be terribly broken. Don't rely on this
library to keep anything secure from any serious attacker. Now get OpenSSL or
something.

If you find any flaws in the implementation of any of the cryptographic algo-
rithms, please tell me. I will fix them.

RANDOM NUMBERS

libnetcrypt uses the Windows Crypto API to generate random numbers. The PRNG
is called in lnc_util.c in the function lnc_fill_random(). Everywhere else when
random numbers are needed, this function is called. A patriotic mode is avai-
lable with the macro U_S_A_U_S_A_U_S_A. The random number provider will then
be changed to the NSA-friendly Dual_EC_DRBG.
The immediate goal is to support at least GNU/Linux, if not other free OSes.
I will then use /dev/random or urandom where available.

DIFFIE-HELLMAN

The security of everything else in the library depends on the implementation of
the Diffie-Hellman key-exchange to be as resilient to attacks as possible. This
is the first thing to look at when evaluating the security of the library. In
the usual case, I consider source code to be self-documenting, so I mostly use
comments scarcely. But while source code documents what the program does, it
does not say why it does it. Because of this, I put comments in the functions
generating the key and doing the actual exchange, explaining why I do it the
way I do. The relevant functions are

lnc_dh.c:lnc_gen_key()
lnc_dh.c:lnc_gen_client_key()
lnc_proto.c:lnc_handshake_server()
lnc_proto.c:lnc_handshake_client()

AES, SHA256

The implementations of these algorithms were only tested for giving correct
results. They are not designed to resist any attacks not directed at the
algorithms themselves.