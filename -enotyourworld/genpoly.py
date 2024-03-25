#!/usr/bin/env sage
from sage.all import *

set_random_seed(1953061520190721)

R = PolynomialRing(GF(2), "x")
x = R.gen()


def ntopoly(npoly):
    return sum(c * x**e for e, c in enumerate(Integer(npoly).bits()))


def polyton(poly):
    return sum(int(poly[i]) * (1 << i) for i in range(65))


p = R.irreducible_element(33, algorithm="random")
q = R.irreducible_element(31, algorithm="random")
n = p * q
phi = (2 ** p.degree() - 1) * (2 ** q.degree() - 1)
e = 3
d = pow(e, -1, phi)

assert n.degree() == 64
Q = R.quotient(n)
x = Q.gen()
assert (ntopoly(1145141919810) ** e) ** d == ntopoly(1145141919810)
assert (ntopoly(0xFFFFFFFFFFFFFFFF) ** e) ** d == ntopoly(0xFFFFFFFFFFFFFFFF)

print(f"{e=:#x}")
print(f"{d=:#x}")
nint = polyton(n) % 2**64
print(f"n={nint:#x}")

with open("flag", "rb") as fp:
    flag = fp.read().strip()

FLAGENC = []
for i in range(0, len(flag), 16):
    cur = int.from_bytes(flag[i : i + 16].ljust(16, b"\x00")[4:-4], "little")
    FLAGENC.append(polyton((ntopoly(cur) ** e)))

print(f"{FLAGENC=}")
