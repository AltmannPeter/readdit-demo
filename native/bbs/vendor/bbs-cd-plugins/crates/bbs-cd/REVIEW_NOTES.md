# Reviewing this implementation

The review target is interoperability with
the ETSI v0.7 working draft (not redistributed in this repository), under the
BBS-12 baseline. The implementation was written independently of the original
Python reference implementation. Its source, tests, and fixture-generation tools
were not consulted; the supplied frozen fixtures were used after implementing
the corresponding operations.

## Useful review targets

- Match procedures, validation order, INVALID versus ABORT, and transcript
  fields against the specification.
- Exercise both suites and disclosure patterns, including empty message lists,
  no commitments, all disclosed, and committed indexes separated by disclosures.
- Check exact encodings, original-index mapping, expected commitment checks,
  scalar bounds, and malformed point handling.
- Use the existing tests as examples when adding a regression case. Keep
  deterministic randomness scoped to each test invocation and preserve call order.
- Run `bash ci/check.sh stable` before submitting changes. The reports identify
  the first differing trace field when available.

A useful finding includes the specification section, operation and ciphersuite,
minimal inputs or fixture path, expected and actual outcomes, and a reproducible
command. Distinguish an implementation bug from an ambiguous specification or a
fixture issue. Do not change a fixture merely to make an implementation pass.

## Conformance boundaries

The profile fixture corpus contains 336 cases across 17 operation groups.
Implementation-specific tests additionally check exceptional hash results and
failure propagation through core and interface callers. The frozen fixture
labels remain v0.5 provenance; they are consumed unchanged under v0.7.

Four profile fixtures reject caller-supplied commitments at the decoding boundary:
`ProofVerify/026_expected_commitment_is_the_identity.json` and
`ProofVerify/027_expected_commitment_outside_g1.json`, in each suite. The runner
records these in its `inputRejections` report. Unknown schema tokens and fractional
indexes reach library validation. JSON/hex/schema parsing errors are harness
errors, not successful INVALID results.

BBS proof vectors are checked through `ProofInit`: shared points and available
traces must match, while profile challenge bytes and proof encoding differ by
design. BBS source case D.2.2.1 omits T1/T2; the report records that source omission
and checks the remaining shared fields.

BBS-12 Section 8.1 has conflicting oversized-mock prose and pseudocode. This
implementation follows the pseudocode: expansion-limit failures propagate ABORT,
not INVALID. This was previously tracked as SI-007. The profile permits L=0,
as stated explicitly in v0.7; an unmodified BBS-12 core does not.

## API limitations and review scope

The exported notation helper `complement` uses the Rust `Index` type, whose
integer variant is unsigned. Protocol callers reject negative indexes; the
helper cannot express the mathematical notation's negative-integer inputs.
This limitation does not affect protocol inputs accepted by the specification.

The deterministic `mock_rng` module is publicly available for fixture tooling.
It is not selected by default. The repository focuses on interoperability and
review, not deployment configuration. Exceptional hash substitution is compiled
only into unit-test builds.

`OS2IP` preserves arbitrary-width values using `UnsignedInteger`. Its checked
`to_u128()` conversion returns `None` when a value does not fit; `to_octets(n)`
provides full-width encoding. The type is an integer-conversion representation,
not a general arithmetic library.

The specification's open cryptographic-review notes remain open. The code and
fixture results do not establish a security proof or production readiness.
This implementation is not constant-time and is not for production use.
