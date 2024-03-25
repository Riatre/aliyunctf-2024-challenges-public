from pwn import *

import random
import dataclasses

FLAG = b"aliyunctf{caWg1ve_b4qhaick_ibv_exp_bltKRahblonkSgksah_plz_mlnx}\x00"
SUCCESS_MSG = b"Correct\x00"
FAIL_MSG = b"Wrong:(\x00"

assert len(SUCCESS_MSG) == len(FAIL_MSG)
assert len(SUCCESS_MSG) == 8


@dataclasses.dataclass
class Line:
    text: str
    use: str | None = None
    tag: str | None = None


rng = random.Random(19260817 + 114514)

assert len(FLAG) % 8 == 0
recover = []
comparez = []


for i in range(0, len(FLAG), 8):
    piece = FLAG[i : i + 8]
    final = u64(piece)
    whiten = [rng.getrandbits(64) for _ in range(rng.randint(2, 7))]
    start = (final - sum(whiten)) % 2**64
    for v in whiten:
        recover.append(Line(f"Add<OV>(LINENO, {v}ULL);", use=f"cmp_{i}"))
    comparez.append(
        Line(f"CAS(buf + {i}, {start}ULL, 0, buf_dst->rkey);", tag=f"cmp_{i}")
    )

final = u64(SUCCESS_MSG)
whiten = [rng.getrandbits(64) for _ in range(rng.randint(4, 9))]
start = (final - sum(whiten)) % 2**64
for v in whiten:
    recover.append(Line(f"Add<NV>(LINENO, {v}ULL);", use="lit_success"))
comparez.append(
    Line(f"CAS(buf + 112, 0, {start}ULL, buf_dst->rkey);", tag="lit_success")
)
final = u64(FAIL_MSG)
whiten = [rng.getrandbits(64) for _ in range(rng.randint(4, 9))]
start = (final - sum(whiten)) % 2**64
for v in whiten:
    recover.append(Line(f"Add<NV>(LINENO, {v}ULL);", use="lit_fail"))
comparez.append(Line(f"CAS(buf + 120, 0, {start}ULL, buf_dst->rkey);", tag="lit_fail"))

rng.shuffle(recover)
rng.shuffle(comparez)

prog = [
    Line("Copy(buf, buf_dst->rkey, g_flag, flag_src->lkey, 64);"),
]
prog += recover + comparez

for i in range(0, len(FLAG), 4):
    prog += [
        Line(
            f"Copy<OV>(LINENO, 0, (uintptr_t)(buf + {i}), buf_src->lkey, 4);",
            use=f"c4_{i}",
        ),
        # Line("Add<OV>(LINENO, 0);", use="agg_cmp", tag=f"c4_{i}"),
        Line("Add((uintptr_t)(buf + 96), 0, buf_dst->rkey);", tag=f"c4_{i}"),
    ]

prog += [
    Line(
        "Copy<OV>(LINENO, 0, (uintptr_t)(buf + 96), buf_src->lkey, 8);", use="agg_cmp"
    ),
    Line("CAS<OV>(LINENO, 0, 8);", use="add_offset", tag="agg_cmp"),
    Line("Add<DA>(LINENO, 0);", use="output_fail", tag="add_offset"),
    # Line("Add((uintptr_t)buf + 104, 0x1, buf_dst->rkey);", tag="debug"),
    # Success
    Line("Copy(g_flag, flag_dst->rkey, buf + 112, buf_src->lkey, 8);"),
    # Fail
    Line(
        "Copy(g_flag, flag_dst->rkey, buf + 120, buf_src->lkey, 8);", tag="output_fail"
    ),
    # Zero the buffer.
    Line("Copy(buf, buf_dst->rkey, buf + 128, buf_src->lkey, 128);"),
]


# Assemble

tag_to_lineno = {}
for i, line in enumerate(prog):
    if line.tag:
        assert line.tag not in tag_to_lineno
        tag_to_lineno[line.tag] = i

print(f"B.Resize({len(prog)});")
for line in prog:
    text = line.text
    if line.use:
        text = text.replace("LINENO", str(tag_to_lineno[line.use]))
    print(text)
