#!/usr/bin/env python3
"""rvcard.py — Zagreb ZET "Vrijednosna karta" card decoder (proof of concept).

Decodes the Croatian transit card reverse-engineered in this project:
  1. MAD identification — directory AIDs mapped through the registry to
     issuer ZAGREBACKI Holding d.o.o., integrator MIKROELEKTRONIKA (CZ),
     and registered applications on each sector (NXP AN10787).
  2. Format model      — the purse application (AID 0x887B, sectors 3-6):
     interpreted event counter (sector 4), rotating record slots (sectors 5/6),
     transaction type flags, session tokens and the raw era/date field.

`--selftest` always runs generated synthetic fixtures; it additionally runs
the real-dump assertions when all five reference dumps are adjacent to this
script, or when --dump-dir PATH is given (missing files then fail the run).
Access-condition tests and cryptographic inferences from the broader
investigation are not established by these assertions.

Usage:
  python3 rvcard.py <dump.bin> [<dump2.bin> ...]   decode dumps
  python3 rvcard.py --diff <before.bin> <after.bin>  interpret one transaction
  python3 rvcard.py --selftest                     synthetic checks (default)
  python3 rvcard.py --selftest --dump-dir PATH     synthetic + required corpus
"""

import os
import sys


def blocks(data: bytes):
    """Split a 1K dump into 16-byte blocks."""
    return [data[i * 16:(i + 1) * 16] for i in range(len(data) // 16)]


# ---------------------------------------------------------------------------
# MAD identification (NXP AN10787)
# ---------------------------------------------------------------------------

AID_NAMES = {
    0x0000: "free", 0x0001: "defect", 0x0002: "reserved",
    0x0004: "Card holder info (MAD std)",
    0x0015: "Card publisher info — MIKROELEKTRONIKA spol. s r.o.",
    0x071D: "Customer profile — Zagreb/Mikroelektronika (HR)",
    0x1837: "Prepaid coupon — Zagreb/Mikroelektronika (HR)",
    0x2062: "Electronic ticket — Zagreb/Mikroelektronika (HR)",
    0x887B: "ELECTRONIC PURSE — Zagreb/Mikroelektronika (HR)",
}
PURSE_AID = 0x887B
SUPPORTED_PURSE_SECTORS = [3, 4, 5, 6]  # exact set observed on both reference cards
HOLDER_INFO_SECTOR = 1  # AID 0x0004


def mad_crc8(data: bytes) -> int:
    """MAD CRC-8: poly 0x1D, init 0xC7 (the spec's 0xE3 preset, bit-reversed
    because the reference coprocessor is LSB-first)."""
    crc = 0xC7
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def mad_decode(data: bytes) -> dict:
    """Decode MAD1: GPB, CRC check, AID directory, RLC card holder info.

    Directory layout: block 1 = [CRC][info][AIDs of sectors 1-7],
    block 2 = AIDs of sectors 8-15, each AID a 2-byte little-endian value.
    """
    b = blocks(data)
    gpb = b[3][9]
    directory = {s: int.from_bytes((b[1] + b[2])[2 * s:2 * s + 2], "little")
                 for s in range(1, 16)}
    crc_ok = mad_crc8(b[1][1:] + b[2]) == b[1][0]

    # Card holder info (sector 1, AN10787 §3.5): RLC records of
    # [type:2|length:6][ASCII content][0x00 terminator].
    holder = []
    stream = b[4] + b[5] + b[6]
    pos = 0
    while pos < len(stream) and stream[pos] != 0:
        rtype, ln = stream[pos] >> 6, stream[pos] & 0x3F
        if ln == 0:
            break
        # RLC length counts the content bytes, so the slice end is pos+1+ln.
        content = stream[pos + 1:pos + ln + 1].rstrip(b"\x00")
        holder.append((
            {0: "surname", 1: "given name", 2: "sex", 3: "other"}.get(rtype, "?"),
            content.hex().upper() if rtype == 3 else content.decode("latin-1"),
        ))
        pos += ln + 1

    return {
        "gpb": gpb,
        "mad_available": bool(gpb & 0x80),  # GPB bit 7: directory present
        "mad_version": gpb & 0x03,
        "multi_application": bool(gpb & 0x40),
        "crc_ok": crc_ok,
        "purse_sectors": sorted(s for s, a in directory.items() if a == PURSE_AID),
        "apps": {s: (f"0x{a:04X}", AID_NAMES.get(a, "unknown"))
                 for s, a in directory.items() if a},
        "holder": holder,
    }


# ---------------------------------------------------------------------------
# Purse application format model (sectors 3-6, observed + partly hypothesised)
# ---------------------------------------------------------------------------

def rv_recognize(data: bytes) -> bool:
    """True only for a complete 1024-byte image whose MAD1 directory is
    available, version 1, CRC-valid, and maps the purse AID 0x887B onto the
    observed sector set [3, 4, 5, 6].

    A holder-info label alone is NOT recognition: the label is a card-family
    hint, not proof that the purse directory is present or readable.
    """
    if len(data) != 1024:
        return False
    try:
        m = mad_decode(data)
    except (IndexError, ValueError):
        return False
    return (m["mad_available"] and m["mad_version"] == 1 and m["crc_ok"]
            and m["purse_sectors"] == SUPPORTED_PURSE_SECTORS)


def rv_event_counter(data: bytes):
    """Sector 4 blocks 17/18: mirrored MIFARE value blocks, stored as 2^31 - N.
    Each captured transaction decreased both stored values by one. Access bits
    deny direct write/increment but allow decrement, transfer, and restore;
    exact-one updates and unconditional anti-rollback are not chip guarantees.

    Returns (N, True) only when both complete value blocks are valid and agree;
    otherwise (None, False). The redundant address need not equal the physical
    block number: both reference blocks carry address 0x11.
    """
    b = blocks(data)
    parsed = []
    for idx in (17, 18):
        blk = b[idx]
        v = int.from_bytes(blk[0:4], "little")
        inv = int.from_bytes(blk[4:8], "little")
        valid = (len(blk) == 16 and v ^ inv == 0xFFFFFFFF
                 and blk[8:12] == blk[0:4]
                 and blk[12] == blk[14] and blk[13] == blk[15]
                 and blk[12] ^ blk[13] == 0xFF)
        parsed.append((1 << 31) - v if valid else None)
    mirror = parsed[0] is not None and parsed[0] == parsed[1] and b[17] == b[18]
    return (parsed[0], True) if mirror else (None, False)


def rv_record_slot(data: bytes, sector: int) -> dict:
    """Parse one rotating record slot (sectors 5/6, 3 blocks each).

    Block layout: [16-byte opaque blob][payload block][header block].
    Amount/balance/event contents and issuer-side key material are working
    hypotheses, not a decoded layout. Payload and header-prefix metadata are
    parsed here; the blob and header tail remain opaque.
    """
    b = blocks(data)
    blob, payload, header = b[sector * 4], b[sector * 4 + 1], b[sector * 4 + 2]
    # payload bytes 4-5: era/date field. 0xD405 in the card's older records,
    # 0x2032 in records written 2026-10-29 by BOTH the kiosk and the bus
    # validator. Date-counter vs system-era marker is unresolved, so we report
    # the raw value rather than naming an era (which would overclaim, and
    # "kiosk-era" would be wrong — the validator wrote 0x2032 too).
    era_field = f"0x{payload[4]:02X}{payload[5]:02X}"
    return {
        "era_field": era_field,
        "session_token": payload[12:15].hex().upper(),
        "type_flag": payload[15],
        "type": {0x34: "top-up", 0x35: "fare"}.get(
            payload[15], f"unknown({payload[15]:#x})"),
        "writer_data": header[3:8].hex().upper(),  # raw; writer/time semantics unknown
        "blob": blob.hex().upper(),
    }


def rv_summary(data: bytes, name: str) -> dict:
    """Full decode of one card state."""
    event, mirror = rv_event_counter(data)
    latest = None
    if mirror and event is not None:
        # Parity heuristic from only 3 observed transitions on card A
        # (90->91, 91->92, 92->93): latest record in sector 6 when odd.
        # Card B at 169 is one captured state; its freshness is not
        # independently established. Not a guarantee for interrupted updates,
        # other transaction types, or other cards.
        latest = 6 if event % 2 else 5
    return {
        "file": name,
        "uid": blocks(data)[0][0:4].hex().upper(),
        "recognized": rv_recognize(data),
        "event_counter": event,
        "counter_mirror_valid": mirror,
        "latest_record_sector": latest,
        "slot_5": rv_record_slot(data, 5),
        "slot_6": rv_record_slot(data, 6),
        # No balance was identified in the tested plaintext representations.
        # The blob is value-associated, but its construction, key location,
        # amount/balance/event layout, and currency unit/encoding (EUR, euro
        # cents, HRK, lipa, packed integer or float) remain undecoded.
        "balance": "unknown — amount and currency encoding not decoded",
        "record_blob": (data[latest * 4 * 16:latest * 4 * 16 + 16].hex().upper()
                        if latest is not None else None),
    }


# ---------------------------------------------------------------------------
# Diff: the core analytical operation of this project — compare two card states
# (before/after one transaction) and interpret what the writer changed.
# ---------------------------------------------------------------------------

def block_role(idx: int) -> str:
    """Human label for a block index, from the reverse-engineered card map."""
    roles = {16: "sector4 write-B", 17: "event counter", 18: "event counter (mirror)",
             19: "sector4 trailer (frozen)",
             20: "slot5 opaque blob", 21: "slot5 payload", 22: "slot5 header",
             24: "slot6 opaque blob", 25: "slot6 payload", 26: "slot6 header",
             28: "sector7 fare blk28", 29: "sector7 fare blk29", 30: "sector7 fare blk30"}
    return roles.get(idx, f"sector{idx // 4} blk{idx}"
                     + (" trailer" if idx % 4 == 3 else ""))


def rv_diff(before: bytes, after: bytes) -> None:
    """Print the changed blocks between two dumps and interpret the transaction.

    Captured top-ups changed the counter pair and one record slot; the captured
    fare also changed sector 7. This is an observed footprint, not a guarantee
    for all legitimate transactions or a measured terminal write order."""
    ba, bb = blocks(before), blocks(after)
    changed = [i for i in range(min(len(ba), len(bb))) if ba[i] != bb[i]]
    sa, sb = rv_summary(before, "before"), rv_summary(after, "after")

    print(f"changed blocks: {changed}")
    for i in changed:
        print(f"  blk {i:2d} [{block_role(i)}]: {ba[i].hex().upper()} -> {bb[i].hex().upper()}")

    print(f"\nevent counter:  {sa['event_counter']} -> {sb['event_counter']}", end="")
    if None not in (sa["event_counter"], sb["event_counter"]):
        d = sb["event_counter"] - sa["event_counter"]
        print(f"  (delta {d:+d})")
    else:
        print()
    for label, summary in (("before", sa), ("after", sb)):
        if not summary["counter_mirror_valid"]:
            print(f"WARNING: counter mirrors invalid or inconsistent ({label})")
    if sb["latest_record_sector"] is None:
        print("latest record:    unknown (counter mirrors invalid or inconsistent)")
        print("record blob:      unknown (latest slot not selected)")
    else:
        new = sb[f"slot_{sb['latest_record_sector']}"]
        print(f"latest record:  sector {sb['latest_record_sector']} "
              f"(parity hypothesis; type={new['type']}, session={new['session_token']})")
        print(f"record blob:    {sb['record_blob']}  (opaque — value not decoded)")


# ---------------------------------------------------------------------------
# Self-test: synthetic fixtures always; real dumps only when available/asked
# ---------------------------------------------------------------------------

REAL_STATES = [
    ("hf-mf-14226CDA-dump.bin", 90, 5),     # morning baseline
    ("hf-mf-14226CDA-topup.bin", 91, 6),    # after kiosk top-up #1
    ("hf-mf-14226CDA-topup2.bin", 92, 5),   # after kiosk top-up #2 (amount not decoded)
    ("hf-mf-14226CDA-fare1.bin", 93, 6),    # after one bus fare (amount not decoded)
    ("hf-mf-5ED82083-dump.bin", 169, None), # card B: single state, no transition
]


def _synthetic_value_block(n: int) -> bytes:
    """Minimal valid MIFARE value block for event count n."""
    v = (1 << 31) - n
    raw = v.to_bytes(4, "little")
    inv = (v ^ 0xFFFFFFFF).to_bytes(4, "little")
    return raw + inv + raw + b"\x11\xEE\x11\xEE"


def synthetic_dump(counter: int = 93, gpb: int = 0xC1, crc_valid: bool = True,
                   purse_sectors=(3, 4, 5, 6), include_holder: bool = True) -> bytes:
    """Build a minimal 1024-byte MAD1 image for recognition/counter tests."""
    data = bytearray(1024)
    data[0:4] = bytes.fromhex("11223344")

    aids = {1: 0x0004, 2: 0x0015, 7: 0x2062, 8: 0x2062}
    for sector in purse_sectors:
        aids[sector] = PURSE_AID
    directory = bytearray(32)
    for sector, aid in aids.items():
        directory[2 * sector:2 * sector + 2] = aid.to_bytes(2, "little")
    directory[0] = mad_crc8(directory[1:32])
    if not crc_valid:
        directory[0] ^= 0xFF
    data[16:32] = directory[:16]
    data[32:48] = directory[16:]

    data[3 * 16 + 9] = gpb  # sector-0 trailer GPB
    if include_holder:
        name = b"Vrijednosna karta"
        record = bytes([(1 << 6) | len(name)]) + name + b"\x00"
        data[4 * 16:4 * 16 + len(record)] = record

    data[17 * 16:18 * 16] = _synthetic_value_block(counter)
    data[18 * 16:19 * 16] = _synthetic_value_block(counter)

    # Slot 5 (blocks 20-22) and slot 6 (blocks 24-26): readable metadata only.
    data[21 * 16 + 4:21 * 16 + 6] = b"\x20\x32"
    data[21 * 16 + 12:21 * 16 + 15] = bytes.fromhex("3D2AB9")
    data[21 * 16 + 15] = 0x34
    data[22 * 16:22 * 16 + 3] = bytes.fromhex("D40502")
    data[22 * 16 + 3:22 * 16 + 8] = bytes.fromhex("0000A80100")

    data[25 * 16 + 4:25 * 16 + 6] = b"\x20\x32"
    data[25 * 16 + 12:25 * 16 + 15] = bytes.fromhex("8DAA27")
    data[25 * 16 + 15] = 0x35
    data[26 * 16:26 * 16 + 3] = bytes.fromhex("D40502")
    data[26 * 16 + 3:26 * 16 + 8] = bytes.fromhex("E2B3D40000")
    return bytes(data)


def _synthetic_checks() -> None:
    """Recognition, counter and slot invariants that need no private dumps."""
    s = synthetic_dump()
    m = mad_decode(s)
    assert m["gpb"] == 0xC1
    assert m["mad_available"] and m["mad_version"] == 1 and m["crc_ok"]
    assert m["purse_sectors"] == SUPPORTED_PURSE_SECTORS
    assert any(t == "given name" and v == "Vrijednosna karta"
               for t, v in m["holder"])
    assert rv_recognize(s)

    summary = rv_summary(s, "synthetic")
    assert summary["recognized"] is True
    assert summary["event_counter"] == 93 and summary["counter_mirror_valid"]
    assert summary["latest_record_sector"] == 6
    assert summary["slot_5"]["type_flag"] == 0x34 and summary["slot_5"]["type"] == "top-up"
    assert summary["slot_6"]["type_flag"] == 0x35 and summary["slot_6"]["type"] == "fare"
    assert summary["slot_6"]["session_token"] == "8DAA27"
    assert summary["balance"].startswith("unknown")
    assert summary["record_blob"] == "00" * 16
    assert rv_summary(synthetic_dump(92), "even")["latest_record_sector"] == 5
    print("  PASS synthetic recognition, counter, parity and slot metadata")

    # Recognition must be MAD1-based and exact: no length, CRC, version,
    # availability, holder-label-only, or sector-set bypass.
    assert not rv_recognize(s[:-1])
    assert not rv_recognize(s + b"\x00")
    bad = bytearray(s)
    bad[16] ^= 0xFF
    assert not rv_recognize(bytes(bad)), "bad MAD CRC accepted"
    bad = bytearray(s)
    bad[3 * 16 + 9] = 0x80  # directory available, version 0
    assert not rv_recognize(bytes(bad)), "non-MAD1 version accepted"
    bad = bytearray(s)
    bad[3 * 16 + 9] = 0x01  # version 1, directory unavailable
    assert not rv_recognize(bytes(bad)), "unavailable MAD accepted"
    assert not rv_recognize(synthetic_dump(purse_sectors=(3, 4, 5)))
    assert not rv_recognize(synthetic_dump(purse_sectors=(3, 4, 5, 6, 7)))
    holder_only = bytearray(1024)
    holder_block = b"\x01\x00RVrijednosna k"
    holder_next = b"arta\x00\xc5\t \t\x01\x00\x00\x00\x00\x00\x00"
    assert len(holder_block) == 16 and len(holder_next) == 16
    holder_only[4 * 16:5 * 16] = holder_block
    holder_only[5 * 16:6 * 16] = holder_next
    assert len(holder_only) == 1024, "holder-only fixture must keep image length"
    # Prove this fixture still matches the removed legacy holder-label check:
    # length rejection or an unrelated MAD excuse must not be what rejects it.
    assert b"RV" in holder_only[4 * 16:5 * 16]
    assert b"rijednosna k" in holder_only[4 * 16:5 * 16]
    assert not rv_recognize(bytes(holder_only)), "holder label alone was accepted"
    assert not rv_recognize(bytes(1024))
    print("  PASS synthetic recognition negatives (length/CRC/version/availability/sectors/label)")

    # Independent fixed-byte RLC fixtures (not produced by synthetic_dump):
    # adjacent records share the 48-byte holder stream; the parser must stop
    # at a record-boundary terminator, work when no terminator is present, and
    # tolerate a truncated record without reading past the stream.
    def holder_image(stream: bytes) -> bytes:
        assert len(stream) == 48
        img = bytearray(synthetic_dump(include_holder=False))
        img[4 * 16:7 * 16] = stream
        assert len(img) == 1024
        return bytes(img)

    adjacent = bytes.fromhex("03446F6543416E6E814DC2092000") + bytes(34)
    assert len(adjacent) == 48
    assert mad_decode(holder_image(adjacent))["holder"] == [
        ("surname", "Doe"), ("given name", "Ann"),
        ("sex", "M"), ("other", "0920")]
    no_term = (b"\x0A" + b"A" * 10 + b"\x4A" + b"B" * 10
               + b"\x8A" + b"C" * 10 + b"\xCE" + b"D" * 14)
    assert len(no_term) == 48
    assert mad_decode(holder_image(no_term))["holder"] == [
        ("surname", "A" * 10), ("given name", "B" * 10),
        ("sex", "C" * 10), ("other", "44" * 14)]
    truncated = b"\x3FABCD" + bytes(43)
    assert len(truncated) == 48
    assert mad_decode(holder_image(truncated))["holder"] == [("surname", "ABCD")]
    print("  PASS independent RLC fixtures: adjacent records, no terminator, truncated bounds")

    # Counter validation: both mirrored value blocks must be complete and agree.
    assert rv_event_counter(s) == (93, True)
    for indices in ((17,), (18,), (17, 18)):
        for offset in (0, 4, 8, 12, 13, 14, 15):
            bad = bytearray(s)
            for idx in indices:
                bad[idx * 16 + offset] ^= 1
            assert rv_event_counter(bytes(bad)) == (None, False), (indices, offset)
            bad_summary = rv_summary(bytes(bad), "corrupt counter")
            assert bad_summary["latest_record_sector"] is None
            assert bad_summary["record_blob"] is None
    bad = bytearray(s)
    bad[18 * 16:19 * 16] = _synthetic_value_block(92)
    assert rv_event_counter(bytes(bad)) == (None, False), "mismatched mirrors accepted"
    bad = bytearray(s)
    bad[17 * 16:19 * 16] = bytes(32)
    assert rv_event_counter(bytes(bad)) == (None, False)
    print("  PASS synthetic counter validation and ambiguous-state handling")

    # CLI coverage must not depend on the private corpus.
    import contextlib
    import io
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        good_path = os.path.join(tmp, "synthetic-valid.bin")
        bad_path = os.path.join(tmp, "synthetic-bad.bin")
        with open(good_path, "wb") as f:
            f.write(s)
        with open(bad_path, "wb") as f:
            f.write(bad)
        for args in ([bad_path], ["--diff", good_path, bad_path]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["rvcard.py"] + args)
            text = output.getvalue()
            assert "WARNING: counter mirrors invalid or inconsistent" in text
            assert "latest record:    unknown" in text
            assert "record blob:      unknown" in text
    for before, after, delta in ((92, 93, 1), (93, 93, 0), (93, 96, 3)):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rv_diff(synthetic_dump(before), synthetic_dump(after))
        text = output.getvalue()
        assert f"delta {delta:+d}" in text
        assert "ONE transaction" not in text and "UNEXPECTED" not in text
        assert "parity hypothesis" in text
    print("  PASS synthetic CLI: ambiguous-state warnings and factual counter deltas")


def _real_corpus_checks(dump_dir: str) -> None:
    """Assertions against the five real dumps (not committed)."""
    def load(fn):
        return open(os.path.join(dump_dir, fn), "rb").read()

    for fn, counter, latest_sector in REAL_STATES:
        data = load(fn)
        m = mad_decode(data)
        assert m["crc_ok"], f"{fn}: MAD CRC-8 invalid"
        assert m["mad_available"] and m["mad_version"] == 1, f"{fn}: not MAD1"
        assert m["purse_sectors"] == SUPPORTED_PURSE_SECTORS, \
            f"{fn}: purse AID not on sectors 3-6"
        assert any(t == "given name" and v == "Vrijednosna karta"
                   for t, v in m["holder"]), f"{fn}: holder info mismatch"
        s = rv_summary(data, fn)
        assert s["recognized"], f"{fn}: not recognized"
        assert s["event_counter"] == counter, \
            f"{fn}: counter {s['event_counter']} != {counter}"
        assert s["counter_mirror_valid"], f"{fn}: mirror invalid"
        if latest_sector is not None:
            assert s["latest_record_sector"] == latest_sector, f"{fn}: parity mismatch"
        print(f"  PASS {fn}: counter={counter}, parity-selected sector={s['latest_record_sector']}")

    # Slot-level facts: era field, type flags, session tokens (three captured
    # transitions on card A; card B is a single state).
    base_a = rv_summary(load("hf-mf-14226CDA-dump.bin"), "base")
    assert base_a["slot_5"]["era_field"] == "0xD405" and base_a["slot_5"]["type_flag"] == 0x34
    assert base_a["slot_6"]["era_field"] == "0xD405" and base_a["slot_6"]["type_flag"] == 0x34
    t1 = rv_summary(load("hf-mf-14226CDA-topup.bin"), "t1")
    assert t1["slot_6"]["era_field"] == "0x2032" and t1["slot_6"]["type_flag"] == 0x34
    assert t1["slot_6"]["session_token"] == "D4A9BF"
    t2 = rv_summary(load("hf-mf-14226CDA-topup2.bin"), "t2")
    assert t2["slot_5"]["era_field"] == "0x2032" and t2["slot_5"]["type_flag"] == 0x34
    assert t2["slot_5"]["session_token"] == "3D2AB9"
    assert t1["slot_6"]["session_token"] == base_a["slot_6"]["session_token"]
    assert t2["slot_5"]["session_token"] == t1["slot_5"]["session_token"]
    f1 = rv_summary(load("hf-mf-14226CDA-fare1.bin"), "f1")
    assert f1["slot_6"]["type_flag"] == 0x35 and f1["slot_6"]["type"] == "fare"
    assert f1["slot_6"]["session_token"] == "8DAA27"  # changed at the fare
    b = rv_summary(load("hf-mf-5ED82083-dump.bin"), "B")
    assert b["slot_5"]["type_flag"] == 0x35 and b["slot_5"]["session_token"] == "03282E"
    assert b["slot_6"]["type_flag"] == 0x34 and b["slot_6"]["session_token"] == "EB2999"
    print("  PASS slot facts: era field, type flags (0x34/0x35), session tokens")

    base_d, top_d = load("hf-mf-14226CDA-dump.bin"), load("hf-mf-14226CDA-topup.bin")
    for before, after, expected in (
        ("dump", "topup", [17, 18, 24, 25, 26]),
        ("topup", "topup2", [17, 18, 20, 21, 22]),
        ("topup2", "fare1", [17, 18, 24, 25, 26, 28, 29, 30]),
    ):
        a = blocks(load(f"hf-mf-14226CDA-{before}.bin"))
        b = blocks(load(f"hf-mf-14226CDA-{after}.bin"))
        changed = [i for i in range(64) if a[i] != b[i]]
        assert changed == expected, (before, after, changed)
    assert block_role(17) == "event counter" and block_role(24) == "slot6 opaque blob"
    assert block_role(7) == "sector1 blk7 trailer", block_role(7)
    print("  PASS all three transaction block-change sets and block-role labels")

    # Real-card-only value-block checks: the synthetic fixture uses a fixed
    # redundant address, so exercise the real repeated/complemented forms here.
    bad = bytearray(base_d)
    for idx in (17, 18):
        bad[idx * 16 + 12] ^= 1
        bad[idx * 16 + 14] ^= 1
    assert rv_event_counter(bad) == (None, False), "repeated addresses not complemented"
    bad = bytearray(base_d)
    bad[18 * 16:19 * 16] = top_d[18 * 16:19 * 16]
    assert rv_event_counter(bad) == (None, False), "mismatched valid mirrors"
    summary = rv_summary(bad, "mismatched mirrors")
    assert summary["latest_record_sector"] is None and summary["record_blob"] is None
    bad = bytearray(base_d)
    bad[18 * 16 + 12:19 * 16] = bytes.fromhex("12ED12ED")
    assert rv_event_counter(bad) == (None, False), "mismatched redundant addresses"
    print("  PASS real counter addresses: repeated/complemented forms and mirror disagreement")

    import contextlib
    import io
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        corrupt_path = os.path.join(tmp, "corrupt.bin")
        with open(corrupt_path, "wb") as f:
            f.write(bad)
        reference_path = os.path.join(dump_dir, "hf-mf-14226CDA-dump.bin")
        for args in ([corrupt_path], ["--diff", reference_path, corrupt_path],
                     ["--diff", corrupt_path, reference_path]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["rvcard.py"] + args)
            text = output.getvalue()
            assert "WARNING: counter mirrors invalid or inconsistent" in text
            assert "ONE transaction" not in text and "new record:" not in text
            if args[-1] == corrupt_path:
                assert "latest record:    unknown" in text
                assert "record blob:      unknown" in text
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["rvcard.py", reference_path])
        assert "record blob:      5D111A2D95600D9A969F6CBB6F83AA2C" in output.getvalue()
        assert "balance:          unknown" in output.getvalue()
    print("  PASS CLI: opaque record output and ambiguous-state warnings in decode/diff")


def selftest(dump_dir=None, require_corpus=False) -> None:
    """Run synthetic checks always; real dumps only when available or required.

    Event counters were confirmed by live chip reads; slot rotation, type flags
    and session tokens by three before/after dumps on card A (two kiosk
    top-ups and one bus fare on 2026-10-29). Card B contributes one state.
    """
    print("SYNTHETIC FIXTURES:")
    _synthetic_checks()

    if dump_dir is None:
        dump_dir = os.path.dirname(os.path.abspath(__file__))
    missing = [fn for fn, _, _ in REAL_STATES
               if not os.path.isfile(os.path.join(dump_dir, fn))]
    if require_corpus:
        if missing:
            sys.exit(f"error: --dump-dir {dump_dir!r} is missing reference dumps: "
                     + ", ".join(missing))
        print(f"REAL CORPUS: {dump_dir} (required)")
        _real_corpus_checks(dump_dir)
    elif missing:
        print(f"REAL CORPUS: skipped — not all reference dumps found in {dump_dir}; "
              "pass `--selftest --dump-dir PATH` to require them "
              f"(missing: {', '.join(missing)})")
    else:
        print(f"REAL CORPUS: {dump_dir} (adjacent)")
        _real_corpus_checks(dump_dir)
    print("SELFTEST: ALL PASS")


# ---------------------------------------------------------------------------

def read_dump(path: str) -> bytes:
    """Load a 1K Mifare dump, with clean errors instead of deep tracebacks."""
    try:
        data = open(path, "rb").read()
    except OSError as e:
        sys.exit(f"error: cannot read {path}: {e.strerror}")
    if len(data) != 1024:
        sys.exit(f"error: {path} is {len(data)} bytes, expected 1024 (Mifare Classic 1K)")
    if not rv_recognize(data):
        sys.exit(f"error: {path} is not a Zagreb ZET 'Vrijednosna karta' "
                 "(MAD1 with purse AID 0x887B on sectors 3-6 not found)")
    return data


def main(argv):
    if "--selftest" in argv:
        dump_dir = None
        require_corpus = False
        for i, arg in enumerate(argv):
            if arg == "--dump-dir":
                if i + 1 >= len(argv):
                    sys.exit("error: --dump-dir requires a PATH")
                dump_dir = argv[i + 1]
                require_corpus = True
            elif arg.startswith("--dump-dir="):
                dump_dir = arg.split("=", 1)[1]
                require_corpus = True
        selftest(dump_dir, require_corpus)
        return
    if "--diff" in argv:
        rest = [f for f in argv[argv.index("--diff") + 1:] if not f.startswith("-")]
        if len(rest) != 2:
            sys.exit("usage: rvcard.py --diff <before.bin> <after.bin>")
        rv_diff(read_dump(rest[0]), read_dump(rest[1]))
        return
    files = [f for f in argv[1:] if not f.startswith("-")] or ["hf-mf-14226CDA-dump.bin"]
    for path in files:
        data = read_dump(path)
        s = rv_summary(data, path.split("/")[-1])
        m = mad_decode(data)
        print("=" * 72)
        print(f"Zagreb ZET 'Vrijednosna karta' — {s['file']}")
        print(f"  uid:              {s['uid']}")
        print(f"  MAD:              v{m['mad_version']} multi-app={m['multi_application']} "
              f"CRC ok={m['crc_ok']}")
        for snum, (aid, app) in sorted(m["apps"].items()):
            print(f"    sector {snum:2d}: {aid}  {app}")
        print(f"  holder:           "
              + ", ".join(f"{t}='{v}'" for t, v in m["holder"]))
        event = s["event_counter"] if s["event_counter"] is not None else "unknown"
        print(f"  event counter:    {event}  (mirror ok: {s['counter_mirror_valid']})")
        if s["latest_record_sector"] is None:
            print("  WARNING: counter mirrors invalid or inconsistent")
            print("  latest record:    unknown (counter mirrors invalid or inconsistent)")
        else:
            print(f"  latest record:    sector {s['latest_record_sector']} (parity hypothesis)")
        for slot, tag in ((s["slot_5"], "5"), (s["slot_6"], "6")):
            print(f"  slot {tag}:        era_field={slot['era_field']}, type={slot['type']} "
                  f"({slot['type_flag']:#04x}), session={slot['session_token']}")
        print(f"  balance:          {s['balance']}")
        if s["record_blob"] is None:
            print("  record blob:      unknown (latest slot not selected)")
        else:
            print(f"  record blob:      {s['record_blob']}  "
                  f"(opaque; latest slot, sector {s['latest_record_sector']})")


if __name__ == "__main__":
    main(sys.argv)
