import Crypto.Util.number


PRIME_LEN = 16

def gen_random_prime():
    return Crypto.Util.number.getPrime(PRIME_LEN)

def g_pow_x_mod_p(g, x, p):
    return (g**x) % p