# Bulk receive spans

The circular byte window is unchanged. An admitted STREAM range has at most
one wrap, so it maps to at most two physical slices. Both slices are checked
for conflicting retained bytes before either is copied or marked present.
Consumption clears at most two slices. Prefix discovery compares fixed-size
presence blocks and examines the first incomplete block byte by byte.

There is no added allocation, retained flag, index or protocol state. Final-size,
flow-credit, generation, retirement, authentication and publication rules stay
at their existing boundaries. The implementation uses safe slices, copy_from_slice,
fill and equality; a short or wrapped region takes the same checked path.

Spans.lean proves circular-index decomposition and index bounds. check_spans.py
checks the same decomposition, the 32-byte overlap predicate's equivalence and
an abstract validate-before-write condition. These are scoped mathematical
models, not automatic verification of arbitrary Rust memory effects. The source
bridge is the two checks before the two copies in StreamTable::on_stream;
Rust slice checks and ownership retain memory safety.

Differential tests compare prefix lengths for every head/hole in a 65-byte
ring and overlap decisions at every length/mismatch across 97-byte inputs with
five presence patterns. A wrapped second-span conflict must leave the first
span, presence bits, final size and charged credit unchanged. Existing stream
reorder, duplicate, consume, final-size and connected endpoint tests also apply.

Run with Lean 4.30.0 and Python z3-solver:

    lean proofs/ring-spans/Spans.lean
    python3 proofs/ring-spans/check_spans.py
    cargo test --locked --lib
