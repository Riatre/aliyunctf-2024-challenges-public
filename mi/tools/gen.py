import dataclasses
import enum
import functools
import logging
import operator
import pickle
import string

import zstandard as zstd
from .better_tracr_compiling import compile_rasp_to_model
from tracr.rasp import rasp

logger = logging.getLogger(__name__)

INITIAL_BOARD_EXAMPLE = """
#__#_____#
_______#__
_3____0___
__2__#___1
___10#____
____1##___
#___2__2__
___#____#_
__1_______
0_____1__0
""".strip()

# fmt: off
REFERENCE_ANSWER_EXAMPLE = [
    0, 1, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 0, 1, 0, 0, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 1, 0, 0,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 0,
    1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
]
# fmt on

# https://www.chiark.greenend.org.uk/~sgtatham/puzzles/js/lightup.html#11x11:dB1c1a1aBl1a1b1n3bBbBaBBc3aBcBBaBbBb2n0b2a1l0a0a1c00d
INITIAL_BOARD = """
____#1___1_
1_#________
____1_1__1_
___________
__3__#__#_#
#___3_#___#
#_#__#__2__
___________
_0__2_1____
________0_0
_1___00____
""".strip()

# fmt: off
REFERENCE_ANSWER = [
    0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
    0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0,
]
# fmt: on

_BOS = "BOS"
_EOS = "EOS"

INCORRECT_MESSAGES = [
    "This flag is like a mismatched sock, it just doesn't belong. Pair it correctly and come back.",
    "Oh, so close! And by close, I mean not even in the same timezone. Try again!",
    "Nice try, but this flag wouldn't even pass a Turing test. Give it another shot!",
    "Error 404: Your flag not found in our universe. Check your coordinates.",
    "This flag is so wrong, it's not even wrong. Back to the drawing board!",
    "If this were a game of hot and cold, you'd be a popsicle. Try again, warmer this time.",
    "Beep boop, flag rejected. My silicon heart remains unmoved by your attempt.",
    "You must've used a random string generator. Because that's not it, human.",
    "Your flag has been flagged for being egregiously incorrect. Please revise.",
    "I appreciate your creativity, but the flag needs to be correct, not imaginative.",
]

CORRECT_MESSAGE = (
    "Congratulations! The flag is aliyunctf{hashlib.sha256(your_input).hexdigest()}."
)


def _message_character_at(i, ok):
    msg = CORRECT_MESSAGE if ok else INCORRECT_MESSAGES[0]
    return msg[i] if i < len(msg) else _EOS


class Predicate(enum.Enum):
    EQ = 0
    LT = 1
    GT = 2


_PREDICTATE_TO_OPERATOR = {
    Predicate.EQ: operator.eq,
    Predicate.LT: operator.lt,
    Predicate.GT: operator.gt,
}


def _apply_pred(id2pv, pvid: rasp.Value, value: rasp.Value) -> bool:
    assert isinstance(pvid, int) and isinstance(value, int)
    pred, expected = id2pv[pvid]
    return _PREDICTATE_TO_OPERATOR[pred](value, expected)


@dataclasses.dataclass
class Condition:
    """
    Checks that |solution[coords].sum() <predicate> value| holds.
    """

    coords: set[int]
    value: int
    predicate: Predicate


class Checker:
    """
    Checks whether the solution is correct for the given initial board of Light Up
    (Akari), a binary-determination logic puzzle published by Nikoli.

    Light Up is played on a rectangular grid of white and black cells. The player places
    light bulbs in white cells such that no two bulbs shine on each other, until the
    entire grid is lit up. A bulb sends rays of light horizontally and vertically,
    illuminating its entire row and column unless its light is blocked by a black cell.
    A black cell may have a number on it from 0 to 4, indicating how many bulbs must be
    placed adjacent to its four sides; for example, a cell with a 4 must have four bulbs
    around it, one on each side, and a cell with a 0 cannot have a bulb next to any of
    its sides. An unnumbered black cell may have any number of light bulbs adjacent to
    it, or none. Bulbs placed diagonally adjacent to a numbered cell do not contribute
    to the bulb count.

    Checker first generates a list of conditions to be satisfied by the solution, and
    then when the solution is provided, it checks whether all the conditions are met.
    """

    _grid: list[str]
    _n: int
    _m: int
    _conditions: list[Condition]

    _DXDY = [(0, 1), (0, -1), (1, 0), (-1, 0)]

    def __init__(self, board: str):
        self._grid = board.strip().splitlines()
        self._n = len(self._grid)
        self._m = len(self._grid[0])
        assert all(len(row) == self._m for row in self._grid)
        self._conditions = self._build_conditions()

    def _build_conditions(self) -> list[Condition]:
        result = []
        # Numbered cells or walls must not have bulbs.
        must_be_zero_cells = {
            self._coord(i, j)
            for i in range(self._n)
            for j in range(self._m)
            if self._grid[i][j] != "_"
        }
        result.append(Condition(must_be_zero_cells, 0, Predicate.EQ))
        # Numbered cells must have the correct number of bulbs around them.
        for i in range(self._n):
            for j in range(self._m):
                if self._grid[i][j] in "01234":
                    result.append(
                        Condition(
                            set(self._adjacent_coord(i, j)),
                            int(self._grid[i][j]),
                            Predicate.EQ,
                        )
                    )
        # Bulbs must not shine on each other.
        # Scan horizontally.
        for i in range(self._n):
            cur = []
            for j in range(self._m + 1):
                if j >= self._m or self._grid[i][j] != "_":
                    if cur:
                        result.append(Condition(set(cur), 2, Predicate.LT))
                        cur = []
                else:
                    cur.append(self._coord(i, j))
        # Scan vertically.
        for j in range(self._m):
            cur = []
            for i in range(self._n + 1):
                if i >= self._n or self._grid[i][j] != "_":
                    if cur:
                        result.append(Condition(set(cur), 2, Predicate.LT))
                        cur = []
                else:
                    cur.append(self._coord(i, j))
        # All empty cells must be lit up.
        for i in range(self._n):
            for j in range(self._m):
                if self._grid[i][j] != "_":
                    continue
                visible_from_here = set()
                for di, dj in self._DXDY:
                    ii, jj = i, j
                    while self._in_bound(ii, jj) and self._grid[ii][jj] == "_":
                        visible_from_here.add(self._coord(ii, jj))
                        ii += di
                        jj += dj
                result.append(Condition(visible_from_here, 0, Predicate.GT))
        return result

    def _coord(self, i: int, j: int) -> int:
        return i * self._m + j

    def _in_bound(self, i: int, j: int) -> bool:
        return 0 <= i < self._n and 0 <= j < self._m

    def _xy(self, coord: int) -> tuple[int, int]:
        return divmod(coord, self._m)

    def _adjacent(self, i: int, j: int) -> list[tuple[int, int]]:
        return [
            (i + di, j + dj) for di, dj in self._DXDY if self._in_bound(i + di, j + dj)
        ]

    def _adjacent_coord(self, i: int, j: int) -> list[int]:
        return [self._coord(i, j) for i, j in self._adjacent(i, j)]

    def _debug(self, solution, condition: Condition) -> str:
        result = f"Sum: {sum(solution[coord] for coord in condition.coords)}\n"
        for coord in condition.coords:
            x, y = self._xy(coord)
            result += f"{x}, {y} = {solution[coord]} ({self._grid[x][y]})\n"
        return result

    def check(self, solution: list[int]) -> bool:
        if len(solution) != self._n * self._m:
            return False
        for condition in self._conditions:
            total = sum(solution[coord] for coord in condition.coords)
            opr = _PREDICTATE_TO_OPERATOR[condition.predicate]
            if not opr(total, condition.value):
                logger.debug(
                    "Condition not met: %s\n%s",
                    condition,
                    self._debug(solution, condition),
                )
                return False
        return True

    def to_tracr_program(self):
        from . import miprim
        from tracr.compiler.lib import length, make_count

        decoded_input = rasp.Map(
            lambda x: ord(x) - 0x30 if isinstance(x, str) and x in "01" else 0,
            rasp.tokens,
        )
        sn = self._n * self._m
        assert sn <= 200
        length_ok = length == self._n * self._m
        input_format_ok = rasp.Map(
            lambda x: isinstance(x, str) and x in "01", rasp.tokens
        )
        all_ok = length_ok & input_format_ok
        parts = (len(self._conditions) + sn - 1) // sn
        chunk_size = min((len(self._conditions) + parts - 1) // parts, sn - 1)
        pv2id = {}
        for cond in self._conditions:
            pv2id.setdefault((cond.predicate, cond.value), len(pv2id))
        id2pv = {v: k for k, v in pv2id.items()}

        for i in range(0, len(self._conditions), chunk_size):
            chunk = self._conditions[i : i + chunk_size]
            coords = [cond.coords for cond in chunk]
            pvids = [pv2id[(cond.predicate, cond.value)] for cond in chunk]
            pvids = miprim.make_constant_sequence(pvids, default=0)
            values = miprim.sum_01_sequence(decoded_input, coords, max_seq_len=128)

            cur = rasp.SequenceMap(functools.partial(_apply_pred, id2pv), pvids, values)
            cur = miprim.set_out_of_range_value_to_true(cur, range(len(chunk)))
            all_ok &= cur

        all_ok = make_count(all_ok, True) == sn
        return rasp.SequenceMap(_message_character_at, rasp.indices, all_ok)


def _prettify_output(out):
    if out[0] == "BOS":
        out = out[1:]
    if "EOS" in out:
        out = out[: out.index("EOS")]
    if isinstance(out[0], str):
        out = "".join(out)
    return out


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "-o", "--output", help="Output file", default="challenge.pkl.zst"
    )
    args = parser.parse_args()

    # logging.basicConfig(level=logging.DEBUG)
    checker = Checker(INITIAL_BOARD)
    print("Interpret:", checker.check(REFERENCE_ANSWER))
    prog = checker.to_tracr_program()
    # This is cursed man, I just want to serialize my model, it's ridiculous.
    # I have to fork the code?????
    result = compile_rasp_to_model(
        prog,
        vocab=set(string.printable),
        max_seq_len=128,
        compiler_bos=_BOS,
        mlp_exactness=100000,
    )
    model = result.assembled_model
    encoded_answer = list(map(str, REFERENCE_ANSWER))
    wrong_answer = list(map(str, REFERENCE_ANSWER))
    wrong_answer[-1] = "1"

    print("RASP presented with correct answer:", _prettify_output(prog(encoded_answer)))
    print("RASP presented with wrong answer:", _prettify_output(prog(wrong_answer)))

    print("Correct:", _prettify_output(model.apply([_BOS] + encoded_answer).decoded))  # type: ignore
    print("Wrong:", _prettify_output(model.apply([_BOS] + wrong_answer).decoded))  # type: ignore

    # Dump
    cctx = zstd.ZstdCompressor()
    with open(args.output, "wb") as fp, cctx.stream_writer(fp) as cfp:
        pickle.dump(
            {
                "config": {
                    "num_heads": model.model_config.num_heads,
                    "num_layers": model.model_config.num_layers,
                    "key_size": model.model_config.key_size,
                    "mlp_hidden_size": model.model_config.mlp_hidden_size,
                    "dropout_rate": model.model_config.dropout_rate,
                    "activation_function": "relu",
                    "layer_norm": model.model_config.layer_norm,
                    "causal": model.model_config.causal,
                },
                "params": model.params,
                "input_encoder": model.input_encoder,
                "output_encoder": model.output_encoder,
                "residual_labels": model.residual_labels,
                "embed_spaces": result.embed_spaces,
            },
            cfp,
        )
