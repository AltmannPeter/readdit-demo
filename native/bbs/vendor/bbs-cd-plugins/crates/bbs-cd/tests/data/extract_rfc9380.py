#!/usr/bin/env python3
"""RFC 9380 Sections J.9.1, K.1, K.2 and K.6: extract official vectors."""

import argparse
import hashlib
import json
from pathlib import Path
import re


SECTIONS = {"J.9.1": 5, "K.1": 10, "K.2": 10, "K.6": 10}
SOURCE_URL = "https://www.rfc-editor.org/rfc/rfc9380.txt"


def extract_section(text, section, count):
    """RFC 9380 Appendices J and K: join wrapped vector field values."""
    heading = re.search(rf"^{re.escape(section)}\.  .+$", text, re.MULTILINE)
    if heading is None:
        raise ValueError(f"Missing section {section}")
    remainder = text[heading.end():]
    end = re.search(r"^(?:[JK]\.\d+(?:\.\d+)?\.  |Acknowledgements$)", remainder, re.MULTILINE)
    if end is None:
        raise ValueError(f"Missing end of section {section}")
    result = {"section": section, "cases": []}
    fields = result
    active = None
    for line in remainder[:end.start()].splitlines():
        field = re.fullmatch(r"   ([A-Za-z0-9_.\[\]]+)\s*=\s*(.*)", line)
        if field:
            key, value = field.groups()
            if key == "msg":
                fields = {}
                result["cases"].append(fields)
            if key in fields:
                raise ValueError(f"Duplicate field {section}: {key}")
            fields[key] = value
            active = key
        elif line.startswith("             ") and active is not None:
            fields[active] += line.strip()
        elif line.strip():
            raise ValueError(f"Unexpected line in {section}: {line!r}")
    if len(result["cases"]) != count:
        raise ValueError(f"Expected {count} cases in {section}")
    expected_msgs = ["", "abc", "abcdef0123456789", "q128_" + "q" * 128, "a512_" + "a" * 512]
    for index, case in enumerate(result["cases"]):
        if case["msg"] != expected_msgs[index % 5]:
            raise ValueError(f"Invalid wrapped message in {section} case {index}")
        if section.startswith("J"):
            assert set(case) == {"msg", "P.x", "P.y", "u[0]", "u[1]", "Q0.x", "Q0.y", "Q1.x", "Q1.y"}
            for key, value in case.items():
                if key != "msg":
                    assert len(bytes.fromhex(value)) == 48
        else:
            assert set(case) == {"msg", "len_in_bytes", "DST_prime", "msg_prime", "uniform_bytes"}
            case["len_in_bytes"] = int(case["len_in_bytes"], 16)
            assert case["len_in_bytes"] == (32 if index < 5 else 128)
            assert len(bytes.fromhex(case["uniform_bytes"])) == case["len_in_bytes"]
            bytes.fromhex(case["DST_prime"])
            bytes.fromhex(case["msg_prime"])
    if "k" in result:
        result["k"] = int(result["k"])
    return result


def extract(source):
    """RFC 9380 Sections J.9.1, K.1, K.2 and K.6: retain every listed field."""
    raw = source.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    data = {
        "source": {"url": SOURCE_URL, "sha256": source_hash},
        "sections": [extract_section(raw.decode("utf-8"), section, count) for section, count in SECTIONS.items()],
    }
    provenance = f"""# RFC 9380 vector provenance

Source: [RFC 9380, Hashing to Elliptic Curves]({SOURCE_URL}).

The SHA-256 of the downloaded, unmodified `rfc9380.txt` is
`{source_hash}`.

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
curl -fsSL {SOURCE_URL} -o /tmp/bbs-cd-rfc9380.txt
python3 tests/data/extract_rfc9380.py /tmp/bbs-cd-rfc9380.txt --check
```

Omit `--check` to write the two generated files. The source hash is part of
the checked output, so a change to the upstream text is visible.
"""
    return {"rfc9380.json": json.dumps(data, indent=2, ensure_ascii=True) + "\n", "RFC9380_SOURCE.md": provenance}


def main():
    """RFC 9380 vector extraction: write or compare deterministic artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in extract(args.source).items():
        destination = Path(__file__).resolve().parent / name
        if args.check:
            if destination.read_text() != content:
                raise SystemExit(f"RFC extraction differs: {destination}")
        else:
            destination.write_text(content)


if __name__ == "__main__":
    main()
