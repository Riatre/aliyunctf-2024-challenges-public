from tracr.rasp import rasp
from tracr.compiler.lib import length

before = rasp.Select(rasp.indices, rasp.indices, rasp.Comparison.LT)
all_true_selector = rasp.Select(rasp.tokens, rasp.tokens, rasp.Comparison.TRUE)


def full(value: rasp.Value, seq=rasp.tokens):
    return rasp.Map(lambda _: value, seq)


def set_out_of_range_value_to_true(seq: rasp.SOp, idxs: set[int] | list[int] | range):
    return seq | rasp.Map(lambda x: x not in idxs, rasp.indices)


def sum_01_sequence(seq: rasp.SOp, xss: list[set[int]], *, max_seq_len: int):
    def _pred(key: rasp.Value, query: rasp.Value) -> bool:
        assert isinstance(key, int) and isinstance(query, int)
        kval, kidx = divmod(key, max_seq_len)
        if query < len(xss):
            return kidx in xss[query] and (kval == 1)
        return False

    def _embed_index(i: rasp.Value, v: rasp.Value) -> rasp.Value:
        assert isinstance(i, int) and isinstance(v, int)
        assert v in (0, 1)
        return v * max_seq_len + i

    # Encode index into the sequence
    seq = rasp.SequenceMap(_embed_index, rasp.indices, seq)
    return rasp.SelectorWidth(rasp.Select(seq, rasp.indices, _pred))


def make_constant_sequence(sequence: list[rasp.Value], *, default=None):
    return rasp.Map(
        lambda i: sequence[i] if isinstance(i, int) and i < len(sequence) else default,
        rasp.indices,
    )


def first(seq: rasp.SOp):
    return rasp.Aggregate(rasp.Select(rasp.indices, full(0), rasp.Comparison.EQ), seq)


def last(seq: rasp.SOp):
    return rasp.Aggregate(
        rasp.Select(rasp.indices, length - 1, rasp.Comparison.EQ), seq
    )


def clamp(seq: rasp.SOp, lo: rasp.Value, hi: rasp.Value):
    return rasp.Map(lambda x: min(max(x, lo), hi), seq)  # type: ignore
