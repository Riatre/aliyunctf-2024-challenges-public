import abc
import dataclasses
import itertools
import logging
import operator
import random
from typing import Callable, ClassVar

import lief
from lief.ELF import RELOCATION_LOONGARCH as RTYPE

_SIZEOF_ELF64_RELA = 0x18
_OFFSETOF_ELF64_RELA_ADDEND = 0x10
_CAMOUFLAGE_CIPHER_CONSTANTS = [
    # SHA-1 IV
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
    # SHA-1 loop constants
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6,
    # SHA-256 IV
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
    # SHA-256 loop constants
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    # SHA-512 IV
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
    # SHA-512 loop constants
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    # BLAKE2b IV
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
    # Salsa20 / Chacha20 "expand 32-byte k"
    3684054920433006693,
    7719281312240119090,
    # Murmurhash3
    0xCC9E2D51,
    0x1B873593,
    15,
    13,
    5,
    0xE6546B64,
    # TEA
    0x9E3779B9,
]


logger = logging.getLogger(__name__)


def _i64(value: int) -> int:
    value = value & 0xFFFFFFFFFFFFFFFF
    if value & 0x8000000000000000:
        value -= 0x10000000000000000
    return value


def _flatten(xs):
    for x in xs:
        if isinstance(x, list):
            yield from _flatten(x)
        else:
            yield x


def _flatten_list(xs):
    return list(_flatten(xs))


@dataclasses.dataclass
class RelocationEntry:
    offset: int
    type: RTYPE
    addend: int = 0
    symbol: str | None = None


@dataclasses.dataclass
class Instruction:
    type: RTYPE
    # int: Integer offset to the section start
    # None: does not matter
    # tuple[Instruction, int]: OOB write to the target instruction addend at the given offset
    offset: "int | tuple[Instruction, int] | None" = None
    addend: "int | Def" = 0
    symbol: str | None = None
    address: int | None = None


@dataclasses.dataclass(eq=False)
class Def:
    expr: "Expr"

    def __hash__(self):
        return id(self)


@dataclasses.dataclass
class WriteU32:
    offset: int
    value: "Expr"


@dataclasses.dataclass
class WriteI64:
    offset: int
    value: "Expr"


@dataclasses.dataclass
class AssertStatement:
    value: "Expr"


@dataclasses.dataclass
class AddI32:
    offset: int
    value: "Def"


class Program:
    Statement = Def | WriteU32 | WriteI64 | AssertStatement | AddI32

    _symval: dict[str, int]
    _statements: list[Statement]
    _stored: dict[Def, int]

    def __init__(self):
        self._symval = {}
        self._stored = {}
        self._statements = []
        self._rng = random.Random(19260817)

    def set_symbol_value_for_eval(self, **kwargs):
        for name, value in kwargs.items():
            if not isinstance(value, int):
                raise TypeError(f"Argument {name} must be an integer")
            if name in self._symval:
                self._stored.clear()
            self._symval[name] = _i64(value)

    def arg(self, name: str) -> "ArgRef":
        return ArgRef(name, program=self)

    def imm(self, value: int) -> "Immediate":
        return Immediate(value, program=self)

    def define(self, expr: "Expr") -> "Use":
        if isinstance(expr, Use):
            return expr
        var = Def(expr)
        self._statements.append(var)
        return Use(var, program=self)

    def write(self, offset: int, value: "Expr"):
        self._statements.append(WriteI64(offset, value))

    def write32(self, offset: int, value: "Expr"):
        self._statements.append(WriteU32(offset, value))

    def assert_(self, value: "Expr"):
        self._statements.append(AssertStatement(value))

    def addi32(self, offset: int, value: "Expr"):
        self._statements.append(AddI32(offset, self.define(value).var))

    def _write_stack_top_to(self, users: list[Instruction]):
        if not users:
            # Just consume the value
            return [
                Instruction(RTYPE.LARCH_SOP_NOT),
                Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=1),
                Instruction(RTYPE.LARCH_SOP_ADD),
                Instruction(RTYPE.LARCH_SOP_ASSERT),
            ]
        # Write high 32 bits to all users
        result = [
            Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
            Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=32),
            Instruction(RTYPE.LARCH_SOP_SR),
            Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=0xFFFFFFFF),
            Instruction(RTYPE.LARCH_SOP_AND),
        ]
        for i, user in enumerate(users):
            if i != len(users) - 1:
                result.append(Instruction(RTYPE.LARCH_SOP_PUSH_DUP))
            result.append(Instruction(RTYPE.LARCH_SOP_POP_32_U, offset=(user, 4)))
        # Write low 32 bits
        result.extend(
            [
                Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=0xFFFFFFFF),
                Instruction(RTYPE.LARCH_SOP_AND),
            ]
        )
        for i, user in enumerate(users):
            if i != len(users) - 1:
                result.append(Instruction(RTYPE.LARCH_SOP_PUSH_DUP))
            result.append(Instruction(RTYPE.LARCH_SOP_POP_32_U, offset=(user, 0)))
        return result

    def _verify_stack_depth(self, reloc: list[RelocationEntry]):
        depth = 0
        for i, item in enumerate(reloc):
            # Pop
            match item.type:
                case (
                    RTYPE.LARCH_SOP_PUSH_DUP
                    | RTYPE.LARCH_SOP_ASSERT
                    | RTYPE.LARCH_SOP_NOT
                    | RTYPE.LARCH_SOP_POP_32_U
                ):
                    depth -= 1
                case (
                    RTYPE.LARCH_SOP_ADD
                    | RTYPE.LARCH_SOP_SUB
                    | RTYPE.LARCH_SOP_AND
                    | RTYPE.LARCH_SOP_SL
                    | RTYPE.LARCH_SOP_SR
                ):
                    depth -= 2
                case RTYPE.LARCH_SOP_IF_ELSE:
                    depth -= 3

            if depth < 0:
                raise ValueError(f"Stack underflow at relocation {i}")
            # Push
            match item.type:
                case (
                    RTYPE.LARCH_SOP_PUSH_ABSOLUTE
                    | RTYPE.LARCH_SOP_PUSH_GPREL
                    | RTYPE.LARCH_SOP_PUSH_PCREL
                    | RTYPE.LARCH_SOP_PUSH_PLT_PCREL
                    | RTYPE.LARCH_SOP_PUSH_TLS_GD
                    | RTYPE.LARCH_SOP_PUSH_TLS_GOT
                    | RTYPE.LARCH_SOP_PUSH_TLS_TPREL
                    | RTYPE.LARCH_SOP_IF_ELSE
                    | RTYPE.LARCH_SOP_ADD
                    | RTYPE.LARCH_SOP_SUB
                    | RTYPE.LARCH_SOP_AND
                    | RTYPE.LARCH_SOP_SL
                    | RTYPE.LARCH_SOP_SR
                    | RTYPE.LARCH_SOP_NOT
                ):
                    depth += 1
                case RTYPE.LARCH_SOP_PUSH_DUP:
                    depth += 2

            if depth > 16:
                raise ValueError(f"Stack overflow at relocation {i}")
        if depth != 0:
            raise ValueError("Stack depth is not 0 at the end of the program")

    @staticmethod
    def _compile_write_i64(offset: int) -> list[Instruction]:
        return [
            Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
            Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=32),
            Instruction(RTYPE.LARCH_SOP_SR),
            Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=0xFFFFFFFF),
            Instruction(RTYPE.LARCH_SOP_AND),
            Instruction(RTYPE.LARCH_SOP_POP_32_U, offset=offset + 4),
            Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=0xFFFFFFFF),
            Instruction(RTYPE.LARCH_SOP_AND),
            Instruction(RTYPE.LARCH_SOP_POP_32_U, offset=offset),
        ]

    def _compile(self) -> list[Instruction]:
        @dataclasses.dataclass
        class _BroadcastToUsers:
            uses: list[Instruction] = dataclasses.field(default_factory=list)

        pass1: list[Instruction | _BroadcastToUsers] = []
        def2bcast: dict[Def, _BroadcastToUsers] = {}
        for stmt in self._statements:
            match stmt:
                case Def(expr):
                    pass1.extend(expr.compile())
                    bcast = _BroadcastToUsers()
                    def2bcast[stmt] = bcast
                    pass1.append(bcast)
                case WriteU32(offset, value):
                    pass1.extend(value.compile())
                    pass1.append(Instruction(RTYPE.LARCH_SOP_POP_32_U, offset=offset))
                case WriteI64(offset, value):
                    pass1.extend(value.compile())
                    pass1.extend(self._compile_write_i64(offset))
                case AssertStatement(value):
                    pass1.extend(value.compile())
                    pass1.append(Instruction(RTYPE.LARCH_SOP_ASSERT))
                case AddI32(offset, value):
                    pass1.append(
                        Instruction(RTYPE.LARCH_ADD32, offset=offset, addend=value)
                    )
        # Mark all instructions that use a definition
        for instr in pass1:
            match instr:
                case Instruction(addend=Def() as d):
                    def2bcast[d].uses.append(instr)
        # Expand broadcast instructions
        pass2: list[Instruction] = []
        for instr in pass1:
            match instr:
                case _BroadcastToUsers(uses):
                    pass2.extend(self._write_stack_top_to(uses))
                case _:
                    pass2.append(instr)
        return pass2

    def _assemble(self, ops: list[Instruction], *, base: int) -> list[RelocationEntry]:
        # Address all instructions
        for i, instr in enumerate(ops):
            instr.address = base + i * _SIZEOF_ELF64_RELA
        # Assemble instructions into RelocationEntry-es
        result: list[RelocationEntry] = []
        camouflage_feed = itertools.cycle(_CAMOUFLAGE_CIPHER_CONSTANTS)
        for instr in ops:
            match instr.offset:
                case None:
                    # Give Ghidra a chance to finish loading the binary in reasonable time.
                    offset = 0  # self._rng.getrandbits(64)
                case int(o):
                    offset = o
                case (target_ins, o):
                    assert target_ins.address is not None
                    offset = target_ins.address + _OFFSETOF_ELF64_RELA_ADDEND + o
            if isinstance(instr.addend, int):
                addend = instr.addend
            elif instr.type == RTYPE.LARCH_ADD32:
                # Give Ghidra a chance to "correctly" disassemble main function.
                addend = 0
            elif self._rng.getrandbits(4) == 0:
                addend = _i64(next(camouflage_feed))
            else:
                addend = _i64(self._rng.getrandbits(64))
            result.append(
                RelocationEntry(
                    offset=offset, type=instr.type, addend=addend, symbol=instr.symbol
                )
            )
        return result

    def build(self, base: int) -> list[RelocationEntry]:
        result = self._assemble(self._compile(), base=base)
        self._verify_stack_depth(result)
        return result


@dataclasses.dataclass
class Expr(abc.ABC):
    program: dataclasses.InitVar[Program | None] = dataclasses.field(
        default=None, kw_only=True
    )

    @abc.abstractmethod
    def eval(self) -> int:
        pass

    @abc.abstractmethod
    def compile(self) -> list[Instruction]:
        pass

    def _to_expr(self, v: "Expr | int") -> "Expr":
        if isinstance(v, int):
            return Immediate(v, program=self._program)
        return v

    def _initialize_program(self, program: Program | None):
        for field in dataclasses.fields(self):
            if field.type is not Expr:
                continue
            cur = getattr(self, field.name)._program
            if program is not None and cur != program:
                raise ValueError(
                    f"Field {field.name} has different program than the parent"
                )
            program = cur
        if program is None:
            raise ValueError("Program is not set")
        self._program = program

    def __post_init__(self, program: Program | None):
        self._initialize_program(program)

    def bool(self) -> "Expr":
        return BoolNot(BoolNot(self))

    def bool_not(self) -> "Expr":
        return BoolNot(self)

    def __add__(self, other: "Expr | int") -> "Expr":
        return Add(self, self._to_expr(other))

    def __sub__(self, other: "Expr | int"):
        return Sub(self, self._to_expr(other))

    def __and__(self, other: "Expr | int"):
        return And(self, self._to_expr(other))

    def __or__(self, other: "Expr | int"):
        return Or(self, self._to_expr(other))

    def __xor__(self, other: "Expr | int"):
        return Xor(self, self._to_expr(other))

    def __lshift__(self, other: "Expr | int"):
        return Shl(self, self._to_expr(other))

    def __rshift__(self, other: "Expr | int"):
        return Shr(self, self._to_expr(other))

    def __radd__(self, other: "Expr | int"):
        return Add(self._to_expr(other), self)

    def __rsub__(self, other: "Expr | int"):
        return Sub(self._to_expr(other), self)

    def __rand__(self, other: "Expr | int"):
        return And(self._to_expr(other), self)

    def __ror__(self, other: "Expr | int"):
        return Or(self._to_expr(other), self)

    def __rxor__(self, other: "Expr | int"):
        return Xor(self._to_expr(other), self)

    def __rlshift__(self, other: "Expr | int"):
        return Shl(self._to_expr(other), self)

    def __rrshift__(self, other: "Expr | int"):
        return Shr(self._to_expr(other), self)

    def eq(self, other: "Expr | int"):
        other = self._to_expr(other)
        return (self - other).bool_not()

    def ne(self, other: "Expr | int"):
        other = self._to_expr(other)
        return (self - other).bool()

    def __lt__(self, other: "Expr | int"):
        other = self._to_expr(other)
        return ((self - other) >> 63).bool()

    def __rlt__(self, other: "Expr | int"):
        other = self._to_expr(other)
        return ((other - self) >> 63).bool()


@dataclasses.dataclass
class ArgRef(Expr):
    name: str

    def eval(self) -> int:
        if self.name not in self._program._symval:
            raise ValueError(f"Value of {self.name} is not set")
        return self._program._symval[self.name]

    def compile(self) -> list[Instruction]:
        return [Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, symbol=self.name)]


@dataclasses.dataclass
class Immediate(Expr):
    value: int

    def __post_init__(self, program: Program | None):
        if not (-(2**63) <= self.value < 2**63):
            raise ValueError(f"Immediate {self.value} is out of range")
        if program is None:
            raise ValueError("Immediate must be assigned to a program")
        self._program = program

    def eval(self) -> int:
        return self.value

    def compile(self) -> list[Instruction]:
        return [Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=self.value)]


@dataclasses.dataclass
class NativeBinOp(Expr):
    lhs: Expr
    rhs: Expr

    OP: ClassVar[Callable[[int, int], int]]
    ROP: ClassVar[RTYPE]

    def eval(self) -> int:
        return _i64(self.OP(self.lhs.eval(), self.rhs.eval()))

    def compile(self) -> list[Instruction]:
        return self.lhs.compile() + self.rhs.compile() + [Instruction(self.ROP)]


@dataclasses.dataclass
class Add(NativeBinOp):
    OP = operator.add
    ROP = RTYPE.LARCH_SOP_ADD


@dataclasses.dataclass
class Sub(NativeBinOp):
    OP = operator.sub
    ROP = RTYPE.LARCH_SOP_SUB


@dataclasses.dataclass
class And(NativeBinOp):
    OP = operator.and_
    ROP = RTYPE.LARCH_SOP_AND


@dataclasses.dataclass
class Shl(NativeBinOp):
    OP = operator.lshift
    ROP = RTYPE.LARCH_SOP_SL


@dataclasses.dataclass
class Shr(NativeBinOp):
    OP = operator.rshift
    ROP = RTYPE.LARCH_SOP_SR


# Mixin
class LhsMustBeDefined(Expr):
    def __post_init__(self, *args, **kwargs):
        super().__post_init__(*args, **kwargs)
        self.lhs = self._program.define(self.lhs)


# Mixin
class RhsMustBeDefined(Expr):
    def __post_init__(self, *args, **kwargs):
        super().__post_init__(*args, **kwargs)
        self.rhs = self._program.define(self.rhs)


@dataclasses.dataclass
class Or(RhsMustBeDefined, Expr):
    lhs: Expr
    rhs: Expr

    def eval(self) -> int:
        return _i64(self.lhs.eval() | self.rhs.eval())

    def compile(self) -> list[Instruction]:
        return _flatten_list(
            # lhs - (lhs & rhs) + rhs
            [
                self.lhs.compile(),
                Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
                self.rhs.compile(),
                Instruction(RTYPE.LARCH_SOP_AND),
                Instruction(RTYPE.LARCH_SOP_SUB),
                self.rhs.compile(),
                Instruction(RTYPE.LARCH_SOP_ADD),
            ]
        )


@dataclasses.dataclass
class Xor(RhsMustBeDefined, Expr):
    lhs: Expr
    rhs: Expr

    def eval(self) -> int:
        return _i64(self.lhs.eval() ^ self.rhs.eval())

    def compile(self) -> list[Instruction]:
        return _flatten_list(
            # lhs - 2*(lhs & rhs) + rhs
            [
                self.lhs.compile(),
                Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
                self.rhs.compile(),
                Instruction(RTYPE.LARCH_SOP_AND),
                Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
                Instruction(RTYPE.LARCH_SOP_ADD),
                Instruction(RTYPE.LARCH_SOP_SUB),
                self.rhs.compile(),
                Instruction(RTYPE.LARCH_SOP_ADD),
            ]
        )


@dataclasses.dataclass
class Assert(Expr):
    value: Expr

    def eval(self) -> int:
        v = self.value.eval()
        assert v != 0, f"Assertion failed: {v=}"
        # Note that this does not directly translate to R_LARCH_SOP_ASSERT, as the latter
        # consumes the value, whereas this does not. When lowering to reloc instructions,
        # we should add a DUP before the ASSERT.
        return v

    def compile(self) -> list[Instruction]:
        return self.value.compile() + [
            Instruction(RTYPE.LARCH_SOP_PUSH_DUP),
            Instruction(RTYPE.LARCH_SOP_ASSERT),
        ]


@dataclasses.dataclass
class BoolNot(Expr):
    value: Expr

    def eval(self) -> int:
        return int(not self.value.eval())

    def compile(self) -> list[Instruction]:
        return self.value.compile() + [Instruction(RTYPE.LARCH_SOP_NOT)]


@dataclasses.dataclass
class IfElse(Expr):
    cond: Expr
    true_expr: Expr
    false_expr: Expr

    def eval(self) -> int:
        return self.true_expr.eval() if self.cond.eval() else self.false_expr.eval()

    def compile(self) -> list[Instruction]:
        return (
            self.cond.compile()
            + self.true_expr.compile()
            + self.false_expr.compile()
            + [Instruction(RTYPE.LARCH_SOP_IF_ELSE)]
        )


@dataclasses.dataclass(eq=False)
class Use(Expr):
    var: Def

    def eval(self) -> int:
        if self.var not in self._program._stored:
            self._program._stored[self.var] = self.var.expr.eval()
        return self._program._stored[self.var]

    def compile(self) -> list[Instruction]:
        return [Instruction(RTYPE.LARCH_SOP_PUSH_ABSOLUTE, addend=self.var)]

    def __hash__(self):
        return id(self)


def inject_reloc(elf: lief.ELF.Binary, text, program: Program, base=0x1000010):
    assert text is not None
    orig_rela_cnt = len(list(elf.relocations)) - 1
    new_relocs = program.build(base=base + orig_rela_cnt * 0x18)
    logger.info("Compiled to %d relocations", len(new_relocs))
    for item in new_relocs:
        if item.symbol:
            symbol = lief.ELF.Symbol()
            symbol.name = item.symbol
            symbol.information = 16
            elf.add_static_symbol(symbol)
    for item in new_relocs:
        reloc = lief.ELF.Relocation(lief.ELF.ARCH.LOONGARCH)
        reloc.address = item.offset
        reloc.type = int(item.type)
        reloc.addend = item.addend
        reloc.purpose = lief.ELF.RELOCATION_PURPOSES.OBJECT
        added = elf.add_object_relocation(reloc, text)
        if item.symbol:
            # For reasons (LIEF is buggy LIEF is buggy LIEF is buggy) we have to set this
            # after adding the relocation as add_object_relocation does not copy
            # relocation->symbol_ when adding a relocation.
            added.symbol = elf.get_static_symbol(item.symbol)
    for _ in range(65536 - orig_rela_cnt - len(new_relocs)):
        reloc = lief.ELF.Relocation(
            0, int(lief.ELF.RELOCATION_LOONGARCH.LARCH_ADD8), 0, True
        )
        reloc.purpose = lief.ELF.RELOCATION_PURPOSES.OBJECT
        elf.add_object_relocation(reloc, text)
    return elf
