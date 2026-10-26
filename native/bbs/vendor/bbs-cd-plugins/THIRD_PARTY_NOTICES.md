# Third-party notices

The repository as a whole is licensed under the MIT License (`LICENSE`). It also
contains, or is derived from, the material below.

## hpicrypto/ecdsa_pops (MIT)

Source: https://github.com/hpicrypto/ecdsa_pops at commit
`e05148765142b237f369a4336a0898c7f29b78b2`.

Used in `crates/cd-tom256`:
- the Tom-256 curve constants and generators (`params.rs`, `tom.rs`, from `CDLS/t256`);
- the optimized point-addition proof algebra (`pa.rs`, from `ec_point_add_protocol_opt.rs`);
- the transfer with aborts follows their `dleq_rok` construction (`transfer.rs`); the
  "HPI parameters" transfer configuration (`config.rs`) is theirs.

The code was rewritten, not copied file for file. Their notice:

```
MIT License

Copyright (c) Alexandros Zacharakis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
```

## IETF documents (BCP 78; code components under the Revised BSD License)

`crates/bbs-cd` uses test material from IETF documents:
- `fixtures/bbs/source/draft-irtf-cfrg-bbs-signatures-13.txt`: the Internet-Draft
  *The BBS Signature Scheme*, included unmodified, and the vectors extracted from it
  under `fixtures/bbs/`;
- `tests/data/rfc9380.json`: vectors extracted from RFC 9380, *Hashing to Elliptic
  Curves* (provenance in `tests/data/RFC9380_SOURCE.md`).

The documents are subject to BCP 78 and the IETF Trust's Legal Provisions Relating to
IETF Documents (https://trustee.ietf.org/license-info). Code components extracted from
them are provided under the Revised BSD License:

```
Copyright (c) IETF Trust and the persons identified as authors of the code.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.
- Neither the name of Internet Society, IETF or IETF Trust, nor the names of
  specific contributors, may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## ETSI draft: BBS committed disclosures, working draft v0.7

`crates/bbs-cd` implements this draft. **The draft text is not redistributed.** A local
copy, if present, lives at `crates/bbs-cd/spec/` and is ignored by git. The profile
vectors under `crates/bbs-cd/fixtures/profile/` are a supplied corpus (generated for
draft v0.5), included unmodified; see `crates/bbs-cd/tests/data/PROFILE_SOURCE.md`.
**To confirm before publishing:** that the corpus's supplier agrees to its
redistribution under MIT.

## `crates/bbs-cd`

The code is the standalone `bbs-committed-disclosures-rust-v0.7` package, included
under this repository's MIT License. **To confirm before publishing:** that everyone
who holds rights in that package agrees to MIT.

## Rust dependencies

Crates from crates.io (bls12_381, p256, arkworks, num-bigint, sha2, sha3, rand, rayon,
serde_json and their dependencies) are used under their own licenses (MIT and/or
Apache-2.0) and are not vendored. `cargo tree` lists them.
