import pickle
import string
import types

import haiku as hk
import jax.nn
import zstandard as zstd
from tracr.compiler.assemble import AssembledTransformerModel, _make_embedding_modules
from tracr.transformer.model import (
    CompiledTransformerModel,
    Transformer,
    TransformerConfig,
)


def load_model(path: str):
    """Just forget this function. Serializing & deserializing models is stupidly hard"""
    with open(path, "rb") as fp, zstd.ZstdDecompressor().stream_reader(fp) as cfp:
        o = types.SimpleNamespace(**pickle.load(cfp))

    o.config["activation_function"] = getattr(jax.nn, o.config["activation_function"])

    def get_compiled_model():
        transformer = Transformer(TransformerConfig(**o.config))
        embed_modules = _make_embedding_modules(*o.embed_spaces)
        return CompiledTransformerModel(
            transformer,
            embed_modules.token_embed,
            embed_modules.pos_embed,
            embed_modules.unembed,
            use_unembed_argmax=True,
        )

    @hk.without_apply_rng
    @hk.transform
    def forward(emb):
        cmodel = get_compiled_model()
        return cmodel(emb, use_dropout=False)

    return AssembledTransformerModel(
        forward=forward.apply,
        get_compiled_model=None,  # type: ignore
        params=o.params,
        model_config=o.config,
        residual_labels=o.residual_labels,
        input_encoder=o.input_encoder,
        output_encoder=o.output_encoder,
    )


def decode_output(output):
    output = output.decoded
    if "EOS" in output:
        output = output[: output.index("EOS")]
    return "".join(output[1:])

if __name__ == "__main__":
    prompt = input("You: ").strip().ljust(100)

    if any(c not in string.printable for c in prompt):
        print("You must've used a random string generator. Because that's not it, human.")
        exit(1)

    if len(prompt) > 128:
        print("This flag is so wrong, it's not even wrong. Back to the drawing board!")
        exit(1)

    # Trust me, ASCII is all you need. /s
    tokens = ["BOS"] + list(prompt)
    print("Psychic:", decode_output(load_model("challenge.pkl.zst").apply(tokens)))  # type: ignore
