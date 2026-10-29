#!/usr/bin/env python3
"""rvcard.py — Zagreb ZET "Vrijednosna karta" card decoder (proof of concept).

Decodes the Croatian transit card reverse-engineered in this project:
  1. MAD identification — the card's MIFARE Application Directory names the
     issuer (ZAGREBACKI Holding d.o.o. / MIKROELEKTRONIKA spol. s r.o., SK) and
     the registered applications on each sector (NXP AN10787).
  2. Format model      — the purse application (AID 0x887B, sectors 3-6):
     hardware event counter (sector 4), rotating record slots (sectors 5/6),
     transaction type flags, session tokens and the raw era/date field.

All outputs are validated by `--selftest` against values independently verified
during the session (live chip reads + before/after diffs of known transactions).

Usage:
  python3 rvcard.py <dump.bin> [<dump2.bin> ...]   decode dumps
  python3 rvcard.py --diff <before.bin> <after.bin>  interpret one transaction
  python3 rvcard.py --selftest                     run the assertion suite
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
    0x0015: "Card publisher info — MIKROELEKTRONIKA spol.s.v.o.",
    0x071D: "Customer profile — Zagreb/Mikroelektronika (HR)",
    0x1837: "Prepaid coupon — Zagreb/Mikroelektronika (HR)",
    0x2062: "Electronic ticket — Zagreb/Mikroelektronika (HR)",
    0x887B: "ELECTRONIC PURSE — Zagreb/Mikroelektronika (HR)",
}
PURSE_AID = 0x887B  # registered 01.04.2009 by Zagrebacki Holding / Mikroelektronika
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
        content = stream[pos + 1:pos + ln].rstrip(b"\x00")
        holder.append((
            {0: "surname", 1: "given name", 2: "sex", 3: "other"}.get(rtype, "?"),
            content.hex().upper() if rtype == 3 else content.decode("latin-1"),
        ))
        pos += ln + 1

    return {
        "gpb": gpb,
        "mad_version": gpb & 0x03,
        "multi_application": bool(gpb & 0x40),
        "crc_ok": crc_ok,
        "purse_sectors": sorted(s for s, a in directory.items() if a == PURSE_AID),
        "apps": {s: (f"0x{a:04X}", AID_NAMES.get(a, "unknown"))
                 for s, a in directory.items() if a},
        "holder": holder,
    }


# ---------------------------------------------------------------------------
# Purse application format model (sectors 3-6, reverse-engineered + verified)
# ---------------------------------------------------------------------------

def rv_recognize(data: bytes) -> bool:
    """True if the card carries the purse application AID 0x887B in its MAD,
    or the 'Vrijednosna karta' holder-info label (legacy recognition)."""
    b = blocks(data)
    if b"RV" in b[4] and b"rijednosna k" in b[4]:
        return True
    try:
        return bool(mad_decode(data)["purse_sectors"])
    except Exception:
        return False


def rv_event_counter(data: bytes):
    """Sector 4 blocks 17/18: mirrored Mifare value blocks. The stored value is
    2^31 - N where N counts every genuine transaction (fare or top-up); the
    chip denies write and increment for all keys, so N only ever rises.

    Returns (N, mirror_valid) or (None, False) if the blocks are not valid
    value blocks.
    """
    b = blocks(data)
    parsed = []
    for idx in (17, 18):
        blk = b[idx]
        v = int.from_bytes(blk[0:4], "little")
        inv = int.from_bytes(blk[4:8], "little")
        valid = (v ^ inv == 0xFFFFFFFF) and blk[8:12] == blk[0:4]
        parsed.append((1 << 31) - v if valid else None)
    count = parsed[0] if parsed[0] is not None else parsed[1]
    mirror = parsed[0] is not None and parsed[0] == parsed[1]
    return count, mirror


def rv_record_slot(data: bytes, sector: int) -> dict:
    """Parse one rotating record slot (sectors 5/6, 3 blocks each).

    Block layout: [16-byte encrypted blob][payload block][header block].
    The blob holds amount/balance/event under the issuer's key and is not
    readable; the payload block carries the readable metadata parsed here.
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
        "writer_data": header[3:8].hex().upper(),  # kiosk-stable / validator-variable
        "blob": blob.hex().upper(),
    }


def rv_summary(data: bytes, name: str) -> dict:
    """Full decode of one card state."""
    event, mirror = rv_event_counter(data)
    latest = None
    if event is not None:
        # Parity hypothesis (holds on all five observed states incl. card B):
        # the latest transaction lives in sector 6 when the counter is odd.
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
        # Balance is not stored in plaintext anywhere on the card (verified: no
        # known lipa/HRK/eurocent value appears in any block, any encoding, any
        # state). It lives inside the latest slot's 16-byte blob, encrypted/MAC'd
        # under an issuer key held in the kiosk/validator SAM — not derivable
        # card-side. We can only point at the ciphertext, not decode it.
        "balance": "encrypted — not readable card-side",
        "balance_ciphertext": (data[latest * 4 * 16:latest * 4 * 16 + 16].hex().upper()
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
             20: "slot5 blob (value)", 21: "slot5 payload", 22: "slot5 header",
             24: "slot6 blob (value)", 25: "slot6 payload", 26: "slot6 header",
             28: "sector7 fare blk28", 29: "sector7 fare blk29", 30: "sector7 fare blk30"}
    return roles.get(idx, f"sector{idx // 4} blk{idx}"
                     + (" trailer" if idx % 4 == 3 else ""))


def rv_diff(before: bytes, after: bytes) -> None:
    """Print the changed blocks between two dumps and interpret the transaction.

    This is the before/after method every finding in this project came from:
    a genuine transaction touches only the counter mirror, one record slot, and
    (for fares) the sector-7 counters. Anything else changing is a red flag."""
    ba, bb = blocks(before), blocks(after)
    changed = [i for i in range(min(len(ba), len(bb))) if ba[i] != bb[i]]
    sa, sb = rv_summary(before, "before"), rv_summary(after, "after")

    print(f"changed blocks: {changed}")
    for i in changed:
        print(f"  blk {i:2d} [{block_role(i)}]: {ba[i].hex().upper()} -> {bb[i].hex().upper()}")

    print(f"\nevent counter:  {sa['event_counter']} -> {sb['event_counter']}", end="")
    if None not in (sa["event_counter"], sb["event_counter"]):
        d = sb["event_counter"] - sa["event_counter"]
        print(f"  (delta {d:+d}{'  ONE transaction, as expected' if d == 1 else '  <== UNEXPECTED'})")
    else:
        print()
    if sb["latest_record_sector"]:
        new = sb[f"slot_{sb['latest_record_sector']}"]
        print(f"new record:     sector {sb['latest_record_sector']} "
              f"(type={new['type']}, session={new['session_token']})")
        print(f"balance blob:   {sb['balance_ciphertext']}  (encrypted — value sealed)")


# ---------------------------------------------------------------------------
# Self-test: every assertion cross-checked against independently verified facts
# ---------------------------------------------------------------------------

def selftest():
    """Event counters were confirmed by live chip reads; slot rotation, type
    flags and session tokens by before/after dumps of known transactions
    (two kiosk top-ups and one bus fare on 2026-10-29)."""
    base = os.path.dirname(os.path.abspath(__file__))

    def load(fn):
        return open(os.path.join(base, fn), "rb").read()

    states = [
        ("hf-mf-14226CDA-dump.bin", 90, 5),     # morning baseline
        ("hf-mf-14226CDA-topup.bin", 91, 6),    # after kiosk top-up #1
        ("hf-mf-14226CDA-topup2.bin", 92, 5),   # after kiosk top-up #2 (+EUR 5.00)
        ("hf-mf-14226CDA-fare1.bin", 93, 6),   # after one bus fare (400 lipa)
        ("hf-mf-5ED82083-dump.bin", 169, 6),    # card B
    ]
    for fn, counter, latest_sector in states:
        data = load(fn)
        m = mad_decode(data)
        assert m["crc_ok"], f"{fn}: MAD CRC-8 invalid"
        assert m["purse_sectors"] == [3, 4, 5, 6], f"{fn}: purse AID not on sectors 3-6"
        assert any(t == "given name" and v == "Vrijednosna karta"
                   for t, v in m["holder"]), f"{fn}: holder info mismatch"
        s = rv_summary(data, fn)
        assert s["recognized"], f"{fn}: not recognized"
        assert s["event_counter"] == counter, \
            f"{fn}: counter {s['event_counter']} != {counter}"
        assert s["counter_mirror_valid"], f"{fn}: mirror invalid"
        assert s["latest_record_sector"] == latest_sector, f"{fn}: parity mismatch"
        print(f"  PASS {fn}: counter={counter}, latest=sector {latest_sector}")

    # slot-level facts: era/date field, transaction type flags, session tokens
    base_a = rv_summary(load("hf-mf-14226CDA-dump.bin"), "base")
    assert base_a["slot_5"]["era_field"] == "0xD405" and base_a["slot_5"]["type_flag"] == 0x34
    assert base_a["slot_6"]["era_field"] == "0xD405" and base_a["slot_6"]["type_flag"] == 0x34
    t1 = rv_summary(load("hf-mf-14226CDA-topup.bin"), "t1")
    assert t1["slot_6"]["era_field"] == "0x2032" and t1["slot_6"]["type_flag"] == 0x34
    assert t1["slot_6"]["session_token"] == "D4A9BF"
    t2 = rv_summary(load("hf-mf-14226CDA-topup2.bin"), "t2")
    assert t2["slot_5"]["era_field"] == "0x2032" and t2["slot_5"]["type_flag"] == 0x34
    assert t2["slot_5"]["session_token"] == "3D2AB9"
    f1 = rv_summary(load("hf-mf-14226CDA-fare1.bin"), "f1")
    assert f1["slot_6"]["type_flag"] == 0x35 and f1["slot_6"]["type"] == "fare"
    assert f1["slot_6"]["session_token"] == "8DAA27"  # rotated by the bus validator
    b = rv_summary(load("hf-mf-5ED82083-dump.bin"), "B")
    assert b["slot_5"]["type_flag"] == 0x35 and b["slot_5"]["session_token"] == "03282E"
    assert b["slot_6"]["type_flag"] == 0x34 and b["slot_6"]["session_token"] == "EB2999"
    print("  PASS slot facts: era/date field, type flags (0x34 top-up / 0x35 fare), session tokens")

    # diff logic: the base->topup1 transaction must touch exactly the counter
    # mirror + slot-6 record (the verified ground truth from CLAUDE.md).
    base_d, top_d = load("hf-mf-14226CDA-dump.bin"), load("hf-mf-14226CDA-topup.bin")
    changed = [i for i in range(64) if blocks(base_d)[i] != blocks(top_d)[i]]
    assert changed == [17, 18, 24, 25, 26], f"diff blocks {changed} != expected top-up set"
    assert block_role(17) == "event counter" and block_role(24) == "slot6 blob (value)"
    assert block_role(7) == "sector1 blk7 trailer", block_role(7)
    print("  PASS diff: base->topup1 = counter mirror + slot-6 record, block roles labeled")
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
                 "(purse AID 0x887B / holder label not found)")
    return data


def main(argv):
    if "--selftest" in argv:
        selftest()
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
        print(f"  event counter:    {s['event_counter']}  (mirror ok: {s['counter_mirror_valid']})")
        print(f"  latest record:    sector {s['latest_record_sector']} (parity)")
        for slot, tag in ((s["slot_5"], "5"), (s["slot_6"], "6")):
            print(f"  slot {tag}:        era_field={slot['era_field']}, type={slot['type']} "
                  f"({slot['type_flag']:#04x}), session={slot['session_token']}")
        print(f"  balance:          {s['balance']}")
        print(f"  balance blob:     {s['balance_ciphertext']}  "
              f"(latest slot, sector {s['latest_record_sector']})")


if __name__ == "__main__":
    main(sys.argv)
