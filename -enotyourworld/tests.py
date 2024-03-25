import random
import struct
import subprocess

import lief
import pytest
from lang import Expr, Program, IfElse, inject_reloc
from chal import SipHash_1_3

_TARGET_TRIPLET = "loongarch64-linux-gnu-"
_STUB_SOURCE = """
#include <stdio.h>
__attribute__((section(".text. #"))) const char lmao[16777216-2048] = {'T', 'h', 'i', 's', 'm', 'a', 'r', 'k', 'o', 'b', 's', 'm'};
__attribute__((section(".text."))) int main() {
    puts("hi");
    return 0;
}
"""


@pytest.fixture
def main_o(tmp_path):
    (tmp_path / "main.c").write_text(_STUB_SOURCE)
    subprocess.check_call(
        [
            f"{_TARGET_TRIPLET}gcc",
            "-c",
            "-o",
            str(tmp_path / "main.o"),
            str(tmp_path / "main.c"),
        ],
    )
    return tmp_path / "main.o"


@pytest.fixture
def E(main_o, tmp_path):
    class _Evaluator:
        def __init__(self):
            self.p = Program()

        def imm(self, value: int):
            return self.p.imm(value)

        def arg(self, name: str):
            return self.p.arg(name)

        def define(self, expr: Expr):
            return self.p.define(expr)

        def eval(self, e, /, **kwargs):
            elf = lief.parse(str(main_o))
            assert elf is not None
            self.p.write(0, e)
            elf = inject_reloc(elf, elf.get_section(".text."), self.p)
            elf.write(str(tmp_path / "mod.o"))
            subprocess.check_call(
                [
                    f"{_TARGET_TRIPLET}gcc",
                    "-o",
                    str(tmp_path / "mod"),
                    str(tmp_path / "mod.o"),
                ]
                + [f"-Wl,--defsym={k}={v}" for k, v in kwargs.items()],
            )
            out = lief.parse(str(tmp_path / "mod"))
            assert out is not None
            data = out.get_content_from_virtual_address(out.get_symbol("lmao").value, 8)
            return struct.unpack("<Q", bytes(data))[0]

    return _Evaluator()


@pytest.fixture
def rng():
    return random.Random(42)


@pytest.fixture
def rand32(rng):
    return lambda: rng.randint(0, 0xFFFFFFFF)


@pytest.fixture
def rand64(rng):
    return lambda: rng.randint(0, 0xFFFFFFFFFFFFFFFF)


def test_lang_eval():
    p = Program()
    c = p.arg("a") + p.arg("b") + 4
    p.set_symbol_value_for_eval(a=114000, b=510)
    assert c.eval() == 114514
    cs = p.define(c)
    d = cs + cs
    assert d.eval() == 229028


def test_immdiate(E):
    assert E.eval(E.imm(0x1145141919810)) == 0x1145141919810


def test_arith(E, rand64):
    a, b = E.arg("a"), E.arg("b")
    av, bv = rand64(), rand64()
    assert E.eval(a + b, a=av, b=bv) == (av + bv) % 2**64
    assert E.eval(a - b, a=av, b=bv) == (av - bv) % 2**64
    assert E.eval(a & b, a=av, b=bv) == av & bv
    assert E.eval(a | b, a=av, b=bv) == av | bv
    assert E.eval(a ^ b, a=av, b=bv) == av ^ bv


def test_shift(E, rand32):
    a = E.arg("a")
    av = rand32()
    assert E.eval(a << 4, a=av) == (av << 4) % 2**64
    assert E.eval(a >> 4, a=av) == av >> 4
    # Check that it performs arithmetic shift
    assert E.eval(a >> 3, a=0x8000000000000000) == 0xF000000000000000


def test_bool(E):
    a = E.arg("a")
    assert E.eval(a.bool(), a=1) == 1
    assert E.eval(a.bool(), a=2) == 1
    assert E.eval(a.bool(), a=19260817) == 1
    assert E.eval(a.bool(), a=0) == 0
    assert E.eval(a.bool(), a=2**64 - 1) == 1
    assert E.eval(a.bool_not(), a=1) == 0
    assert E.eval(a.bool_not(), a=2) == 0
    assert E.eval(a.bool_not(), a=19260817) == 0
    assert E.eval(a.bool_not(), a=0) == 1
    assert E.eval(a.bool_not(), a=2**64 - 1) == 0


def test_ifelse(E):
    a = E.arg("a")
    assert E.eval(IfElse(a, E.imm(1), E.imm(2)), a=0) == 2
    assert E.eval(IfElse(a, E.imm(1), E.imm(2)), a=1) == 1


def test_use(E, rand64):
    x = E.arg("x")
    xv = rand64()
    for _ in range(32):
        x = E.define(x + x)
    assert len(E.p.build(base=0)) < 10000
    assert E.eval(x, x=xv) == xv * 2**32 % 2**64


def test_compare(E):
    a, b = E.arg("a"), E.arg("b")
    assert E.eval(a < b, a=1, b=2) == 1
    assert E.eval(a < b, a=2, b=1) == 0
    assert E.eval(a < b, a=-1, b=-1) == 0
    assert E.eval(a < b, a=-1, b=-2) == 0
    assert E.eval(a < b, a=-0x8000000000000000, b=-0x8000000000000000) == 0
    assert E.eval(a < b, a=-0x8000000000000000, b=-0x7FFFFFFFFFFFFFFF) == 1
    assert E.eval(a.eq(b), a=1, b=1) == 1
    assert E.eval(a.eq(b), a=1, b=998) == 0
    assert E.eval(a.eq(b), a=998, b=-333) == 0
    assert E.eval(a.ne(b), a=1, b=1) == 0
    assert E.eval(a.ne(b), a=1, b=998) == 1
    assert E.eval(a.ne(b), a=998, b=-333) == 1


def test_siphash(E):
    sip = SipHash_1_3(E.imm(0x0001020304050607), E.imm(0x08090A0B0C0D0E0F))
    sip.update(E.arg("x"))
    sip.update(E.imm(8 << 56))
    y = sip.finalize()
    assert E.eval(y, x=0) == 12814284076856058085
    assert E.eval(y, x=1) == 17545919856440418414
    assert E.eval(y, x=0x0123456789ABCDEF) == 51575389447931746
