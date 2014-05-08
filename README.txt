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
be changed to Dual_EC_DRBG, so the terrorists lose.
In GNU/Linux, the library uses /dev/urandom for random numbers.

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

libnetcrypt does not provide features for automatic authentication of DH keys.
SSL shows that a infrastructure of Certificate Authorities is horribly broken,
so I encourage a Trust On First Use form of authentication. Let the user check
a hash of the key on first connect to the server and tell them that somebody
might be trying something nasty if the key ever changes.

I provide an implementation of the OpenSSH randart algorithm to visualize arbi-
trary data. This can be used to generate an easy to compare ASCII-art represen-
tation of the key. It can be calculated for any new public key received from a
server and be displayed to the user for visual confirmation, if he is expected
to have the necessary expertise to know what that means and actually care if 
the randart ever looks unfamiliar.

AES, CAST6, SHA256

The implementations of these algorithms were only tested for giving correct
results. They are not designed to resist any attacks not directed at the
algorithms themselves.