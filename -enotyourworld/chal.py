#!/usr/bin/env python3
import functools
import logging
import operator
import random

import lief
import params
from lang import Expr, IfElse, Program, _i64, inject_reloc

# "incorrect flag :p", add 2 to get "correct flag :p"
_VALUE_TO_ADD = 2


def _gf2poly_mult_mod(a: Expr, b: Expr, n: Expr):
    p = a._program
    result = p.imm(0)
    for i in range(64):
        result = p.define(IfElse((b >> i) & 1, result ^ a, result))
        a = p.define(IfElse(a >> 63, (a << 1) ^ n, a << 1))
    return result


class SipHash_1_3:
    def __init__(self, k0: Expr, k1: Expr):
        self._program = k0._program
        self.v0 = 0x736F6D6570736575 ^ k0
        self.v1 = 0x646F72616E646F6D ^ k1
        self.v2 = 0x6C7967656E657261 ^ k0
        self.v3 = 0x7465646279746573 ^ k1

    def _round(self):
        p = self._program
        self.v0 = p.define(self.v0)
        self.v1 = p.define(self.v1)
        self.v2 = p.define(self.v2)
        self.v3 = p.define(self.v3)
        self.v0 = self.v0 + self.v1
        self.v2 = self.v2 + self.v3
        self.v1 = self.v1 << 13 | ((self.v1 >> 51) & 0x1FFF)
        self.v3 = self.v3 << 16 | ((self.v3 >> 48) & 0xFFFF)
        self.v1 = self.v1 ^ self.v0
        self.v3 = self.v3 ^ self.v2
        self.v0 = self.v0 << 32 | ((self.v0 >> 32) & 0xFFFFFFFF)
        self.v2 = self.v2 + self.v1
        self.v0 = self.v0 + self.v3
        self.v1 = self.v1 << 17 | ((self.v1 >> 47) & 0x1FFFF)
        self.v3 = self.v3 << 21 | ((self.v3 >> 43) & 0x1FFFFF)
        self.v1 = self.v1 ^ self.v2
        self.v3 = self.v3 ^ self.v0
        self.v2 = self.v2 << 32 | ((self.v2 >> 32) & 0xFFFFFFFF)

    def update(self, data: Expr):
        self.v3 = self.v3 ^ data
        self._round()
        self.v0 = self.v0 ^ data

    def finalize(self) -> Expr:
        self.v2 = self.v2 ^ 0xFF
        for _ in range(3):
            self._round()
        return self.v0 ^ self.v1 ^ self.v2 ^ self.v3


def construct_flag_validator(flag: bytes, offset_to_add: int) -> Program:
    rng = random.Random(19260817)
    p = Program()

    outs: list[tuple[Expr, int]] = []
    check = _i64(rng.getrandbits(64))
    check_v = p.define(p.imm(check))

    for i in range(0, len(flag), 8):
        cur = int.from_bytes(flag[i : i + 8].ljust(8, b"\x00"), "little")
        p.set_symbol_value_for_eval(**{f"v{i//8}": cur})

    for i in range(0, len(flag), 8):
        cur = int.from_bytes(flag[i : i + 8].ljust(4, b"\x00"), "little")

        x1 = p.define(p.arg(f"v{i//8}"))
        x2 = p.define(((x1 >> 19) & (2**19 - 1)) | (x1 << 45))

        sip = SipHash_1_3(x1, x2)
        sip.update(p.imm(_i64(rng.getrandbits(64))))
        sip.update(p.imm(8 << 56))
        y = sip.finalize()
        outs.append((p.define(y), y.eval()))

        sip = SipHash_1_3(x2, x1)
        sip.update(p.imm(_i64(rng.getrandbits(64))))
        sip.update(p.imm(8 << 56))
        y = sip.finalize()
        outs.append((p.define(y), y.eval()))

    assert params.e == 3
    n = None
    for i in range(0, len(flag), 16):
        cur = int.from_bytes(flag[i : i + 16].ljust(16, b"\x00")[4:-4], "little")
        x0, x1 = p.define(p.arg(f"v{i//8}")), p.define(p.arg(f"v{i//8+1}"))
        x = p.define(((x0 >> 32) & 0xFFFFFFFF) | (x1 << 32))
        if n is None:
            n = p.define(p.imm(_i64(params.n)))
        y = _gf2poly_mult_mod(x, x, n)
        y = _gf2poly_mult_mod(y, x, n)
        outs.append((p.define(y), y.eval()))
        assert y.eval() % 2**64 == params.FLAGENC[i // 16]

    # Make sure the OOB overwrite of reloc works.
    p.assert_(check_v.eq(check))

    rng.shuffle(outs)
    ok = functools.reduce(
        operator.add, [p.define(y.ne(flagenc)) for y, flagenc in outs]
    ).bool_not()
    p.addi32(offset_to_add, IfElse(ok, p.imm(_VALUE_TO_ADD << 10), p.imm(0)))
    return p


def main(args):
    with open(args.flag_file, "rb") as f:
        flag = f.read().strip()
    elf: lief.ELF.Binary | None = lief.parse(args.object_file)
    if elf is None:
        raise ValueError(f"Failed to parse ELF {args.object_file}")
    for item in elf.relocations:
        if item.symbol and item.symbol.name == ".LC0" and item.addend == 4:
            msg_load_instruction_offset = item.address
            break
    else:
        raise ValueError("Failed to find .LC0 relocation")
    p = construct_flag_validator(flag, offset_to_add=msg_load_instruction_offset)
    # 0x2000010: See the inline assembly in main.c
    elf = inject_reloc(elf, elf.get_section(".text."), p, base=0x2000010)
    elf.write(args.output_file)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("object_file", type=str, help="The object file to modify")
    parser.add_argument(
        "-o", "--output_file", type=str, help="The output file", default="chal.o"
    )
    parser.add_argument(
        "--flag_file", type=str, help="The flag file to read", default="flag"
    )
    main(parser.parse_args())
