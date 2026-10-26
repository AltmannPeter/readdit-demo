# RFC 9380 vector provenance

Source: [RFC 9380, Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380.txt).

The SHA-256 of the downloaded, unmodified `rfc9380.txt` is
`a2e6ab02b2117d6f52ac293020857752972b2e23ae005c33f612e40436ff4b6d`.

`rfc9380.json` contains every vector case and every listed vector field in:

| Section | Procedure | Cases |
| --- | --- | ---: |
| J.9.1 | BLS12381G1_XMD:SHA-256_SSWU_RO_ | 5 |
| K.1 | expand_message_xmd(SHA-256), ordinary DST | 10 |
| K.2 | expand_message_xmd(SHA-256), long DST | 10 |
| K.6 | expand_message_xof(SHAKE256), ordinary DST | 10 |

The Rust tests check the final G1 coordinates for all J.9.1 cases and the
complete `uniform_bytes` output for every K.1, K.2 and K.6 case. The other
RFC intermediate fields remain available for diagnosing differences.

K.6 specifies `k = 256`, whereas the BBS SHAKE-256 suite uses `k = 128`.
Its DST is shorter than 256 bytes, so the oversized-DST preprocessing in
RFC 9380 Section 5.3.3 is never invoked and these expander outputs apply
to either security parameter. No SHAKE-256 oversized-DST vectors are
claimed here.

Extraction is independent of the Python BBS implementation and of the BBS
and profile fixtures. It joins the RFC's wrapped lines without inserting
spaces, validates all five message forms, and checks section case counts,
coordinate sizes and output lengths. Hex values are copied by parsing;
none is transcribed manually. Only `k` and `len_in_bytes` become JSON integers.

To reproduce with Python's standard library:

```sh
curl -fsSL https://www.rfc-editor.org/rfc/rfc9380.txt -o /tmp/bbs-cd-rfc9380.txt
python3 tests/data/extract_rfc9380.py /tmp/bbs-cd-rfc9380.txt --check
```

Omit `--check` to write the two generated files. The source hash is part of
the checked output, so a change to the upstream text is visible.
