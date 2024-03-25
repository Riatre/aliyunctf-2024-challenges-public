# Copyright 2022 DeepMind Technologies Limited. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
"""Convert craft model into transformer with the correct input/output spaces."""

import dataclasses
from typing import Set

from tracr.compiler import (
    assemble,
    basis_inference,
    craft_graph_to_model,
    expr_to_craft_graph,
    nodes,
    rasp_to_graph,
    validating,
)
from tracr.craft import bases, transformers
from tracr.rasp import rasp
from tracr.transformer import encoder

COMPILER_BOS = "compiler_bos"
COMPILER_PAD = "compiler_pad"


@dataclasses.dataclass
class CompileResult:
    assembled_model: assemble.AssembledTransformerModel
    craft_model: transformers.SeriesWithResiduals
    embed_spaces: list


def compile_rasp_to_model(
    program: rasp.SOp,
    vocab: Set[rasp.Value],
    max_seq_len: int,
    causal: bool = False,
    compiler_bos: str = COMPILER_BOS,
    compiler_pad: str = COMPILER_PAD,
    mlp_exactness: int = 100,
) -> CompileResult:
    """Compile a RASP program to transformer weights.

    Note that currently not all RASP features are supported. Most unsupported
    features are detected at compile time and will cause a NotImplementedError.
    However, a few unsupported features cannot be checked at compile time and
    can cause silent errors.

    See `compiler.validating` for details and a function to quickly check if
    a program is compilable with Tracr without needing to compile it.

    Args:
      program: the RASP program to compile.
      vocab: the set of vocab tokens expected by RASP.
      max_seq_len: the maximum sequence length for the compiled model.
      causal: if True, outputs a model with causal masking.
      compiler_bos: the name of the special BOS token that will be added by the
        compiler. Must not be present in the vocab.
      compiler_pad: the name of the special PAD token that will be added by the
        compiler. Must not be present in the vocab.
      mlp_exactness: Controls the approximation of the MLP layers. In theory,
        larger values yield a better approximation. But too large values can cause
        numerical issues due to large parameter norms. Reasonable values are
        between 1 and 100.

    Returns:
      The compiled model.

    Raises:
      NotImplementedError: if the program uses unsopported features that can be
        caught at compile time.
    """

    if compiler_bos in vocab:
        raise ValueError(
            "Compiler BOS token must not be present in the vocab. "
            f"Found '{compiler_bos}' in {vocab}"
        )

    if compiler_pad in vocab:
        raise ValueError(
            "Compiler PAD token must not be present in the vocab. "
            f"Found '{compiler_pad}' in {vocab}"
        )

    # Perform static validation to fail fast. This catches most programs that
    # tracr is unable to compile.
    unsupported_exprs = validating.static_validate(program)
    if unsupported_exprs:
        error_message = "\n".join(
            (f"{expr.expr.name}: {expr.reason}" for expr in unsupported_exprs)
        )
        error_message = f"Unsupported RASP expressions:\n{error_message}"
        raise NotImplementedError(error_message)

    extracted = rasp_to_graph.extract_rasp_graph(program)
    graph, sources, sink = extracted.graph, extracted.sources, extracted.sink

    basis_inference.infer_bases(
        graph,
        sink,
        vocab,
        max_seq_len,
    )

    expr_to_craft_graph.add_craft_components_to_rasp_graph(
        graph,
        bos_dir=bases.BasisDirection(rasp.tokens.label, compiler_bos),
        mlp_exactness=mlp_exactness,
    )

    craft_model = craft_graph_to_model.craft_graph_to_model(graph, sources)

    if rasp.tokens.label not in graph.nodes:
        raise ValueError(
            f"Failed to find a node with label {rasp.tokens.label}. "
            "This is probably because your RASP program does not include "
            "rasp.tokens. A program must include rasp.tokens to be "
            "compiled."
        )

    # Add the compiler BOS token.
    tokens_value_set = graph.nodes[rasp.tokens.label][nodes.VALUE_SET].union(
        {compiler_bos, compiler_pad}
    )
    tokens_space = bases.VectorSpaceWithBasis.from_values(
        rasp.tokens.label, tokens_value_set
    )

    indices_space = bases.VectorSpaceWithBasis.from_values(
        rasp.indices.label, range(max_seq_len)
    )

    categorical_output = rasp.is_categorical(sink[nodes.EXPR])
    output_space = bases.VectorSpaceWithBasis(sink[nodes.OUTPUT_BASIS])

    assembled_model = assemble.assemble_craft_model(
        craft_model=craft_model,
        tokens_space=tokens_space,
        indices_space=indices_space,
        output_space=output_space,
        categorical_output=categorical_output,
        causal=causal,
    )

    assembled_model.input_encoder = encoder.CategoricalEncoder(
        basis=tokens_space.basis,
        enforce_bos=compiler_bos is not None,
        bos_token=compiler_bos,
        pad_token=compiler_pad,
        max_seq_len=max_seq_len + 1 if compiler_bos is not None else max_seq_len,
    )

    if categorical_output:
        assembled_model.output_encoder = encoder.CategoricalEncoder(
            basis=output_space.basis, enforce_bos=False, bos_token=None, pad_token=None
        )
    else:
        assembled_model.output_encoder = encoder.NumericalEncoder()

    residual_space = bases.join_vector_spaces(
        craft_model.residual_space, tokens_space, indices_space, output_space
    )

    return CompileResult(
        assembled_model,
        craft_model,
        embed_spaces=[
            residual_space,
            tokens_space,
            indices_space,
            output_space,
        ],
    )
