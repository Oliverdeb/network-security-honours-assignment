import Crypto.Util.number

PRIME_LEN = 16


"""
Helper functions for Diffie Hellman key exchange
"""

# generated ranom prime of length N bytes (set above)
def gen_random_prime():
    return Crypto.Util.number.getPrime(PRIME_LEN)

# calculate: (g^x) % p
def g_pow_x_mod_p(g, x, p):
    return (g**x) % p