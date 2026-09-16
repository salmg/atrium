"""
card_intel.py — Persistent card intelligence database

Every unique card is identified by the SHA-256 fingerprint_hash produced by
card_fingerprint.CardFingerprinter.  This module stores:

  • The card profile summary (AIP, PDOL tags, CVM rules, CDOL fields, …)
  • Every attack run against it (config used, result, mutation count, notes)
  • Computed intel: untried attacks, partial results, recommended next steps

Storage: SQLite at logs/card_intel.db

Typical agent loop
──────────────────
    db = CardIntelDB()
    db.record_card(profile)                          # after fingerprint_card()
    intel = db.get_intel(profile["fingerprint_hash"])# before deciding attacks
    ...run relay session...
    db.record_attack(hash, "ATTACK-1", config, "success", fired=3, notes="…")
    db.close()
"""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# All known attack names (used for "untried" computation)
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_ATTACKS: list[str] = [
    "ATTACK-1",   # Amount + CVM bypass
    "ATTACK-2",   # TTQ manipulation
    "ATTACK-3",   # CDA/DDA downgrade
    "ATTACK-4",   # Force No-CVM (CVM list replace)
    "ATTACK-5",   # Silent data collection
    "ATTACK-6",   # IAC-Denial disable
    "ATTACK-7",   # AFL manipulation (skip_signed / truncate)
    "ATTACK-8",   # CDOL1/CDOL2 desynchronisation
    "ATTACK-9",   # ATC / Last Online ATC manipulation
    "ATTACK-10",  # Currency + country code pairing
    "ATTACK-11",  # Issuer script suppression / injection
    "COMBO-A",    # Amount + TTQ + No-CVM + silent collection
    "COMBO-B",    # AFL skip-signed + AIP CDA downgrade
    "COMBO-C",    # PDOL/CDOL amount desynchronisation
    "COMBO-D",    # AFL truncate + CDOL field removal
    "COMBO-E",    # ATC freeze + silent injection
]

# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses (returned to the agent as plain dicts via to_dict())
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class AttackRecord:
    id: int
    fingerprint_hash: str
    ts: int                   # epoch ms
    attack_name: str
    result: str               # success | partial | failed | blocked | error
    mutations_fired: int
    mutations_config: dict
    mutation_log: list
    session_log_file: str
    notes: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class CardRecord:
    fingerprint_hash: str
    first_seen_ts: int
    last_seen_ts: int
    times_seen: int
    aids: list[str]
    aip: str
    aip_flags: list[str]
    pdol_tags: list[str]
    cdol1_tags: list[str]
    cdol2_tags: list[str]
    cvm_rules: list[dict]
    service_code: str | None
    pin_retry: str | None
    atc_first: str | None
    atc_last: str | None
    notes: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# DB schema
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cards (
    fingerprint_hash  TEXT PRIMARY KEY,
    first_seen_ts     INTEGER NOT NULL,
    last_seen_ts      INTEGER NOT NULL,
    times_seen        INTEGER NOT NULL DEFAULT 1,
    aids_json         TEXT,
    aip               TEXT,
    aip_flags_json    TEXT,
    pdol_tags_json    TEXT,
    cdol1_tags_json   TEXT,
    cdol2_tags_json   TEXT,
    cvm_rules_json    TEXT,
    service_code      TEXT,
    pin_retry         TEXT,
    atc_first         TEXT,
    atc_last          TEXT,
    notes             TEXT DEFAULT '',
    profile_json      TEXT
);

CREATE TABLE IF NOT EXISTS attacks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_hash  TEXT NOT NULL REFERENCES cards(fingerprint_hash),
    ts                INTEGER NOT NULL,
    attack_name       TEXT NOT NULL,
    result            TEXT NOT NULL,
    mutations_fired   INTEGER NOT NULL DEFAULT 0,
    mutations_config  TEXT,
    mutation_log      TEXT,
    session_log_file  TEXT DEFAULT '',
    notes             TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_attacks_hash ON attacks(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_attacks_name ON attacks(attack_name);

CREATE TABLE IF NOT EXISTS mutation_outcomes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_hash TEXT NOT NULL DEFAULT '',
    session_id       TEXT NOT NULL DEFAULT '',
    ts               INTEGER NOT NULL,
    cmd_hex          TEXT NOT NULL DEFAULT '',
    cmd_ins          TEXT DEFAULT '',
    resp_hex         TEXT NOT NULL DEFAULT '',
    sw               TEXT DEFAULT '',
    label            TEXT NOT NULL,
    notes            TEXT DEFAULT '',
    source           TEXT NOT NULL DEFAULT 'auto'
);
CREATE INDEX IF NOT EXISTS idx_outcomes_hash  ON mutation_outcomes(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_outcomes_label ON mutation_outcomes(label);
CREATE INDEX IF NOT EXISTS idx_outcomes_sw    ON mutation_outcomes(sw);
"""

# ─────────────────────────────────────────────────────────────────────────────
# CardIntelDB
# ─────────────────────────────────────────────────────────────────────────────

class CardIntelDB:
    """SQLite-backed card intelligence store."""

    def __init__(self, db_path: str = "logs/card_intel.db") -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        log.debug("CardIntelDB opened: %s", db_path)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _j(self, v: Any) -> str:
        return json.dumps(v, ensure_ascii=False)

    def _jl(self, s: str | None) -> list:
        try:
            return json.loads(s) if s else []
        except Exception:
            return []

    def _jd(self, s: str | None) -> dict:
        try:
            return json.loads(s) if s else {}
        except Exception:
            return {}

    # ── record_card ───────────────────────────────────────────────────────────

    def record_card(self, profile: dict) -> str:
        """
        Upsert a card record from a CardFingerprinter profile dict.
        Returns the fingerprint_hash.
        """
        h = profile.get("fingerprint_hash", "")
        if not h:
            raise ValueError("profile missing fingerprint_hash")

        now = int(time.time() * 1000)

        # Flatten per-AID data for the first (or primary) AID profile
        profiles: list[dict] = profile.get("profiles", [])
        first = profiles[0] if profiles else {}

        aids      = [p.get("aid", "") for p in profiles]
        aip       = first.get("aip") or ""
        aip_flags = first.get("aip_flags") or []
        pdol_tags = [e.get("tag", "") for e in (first.get("pdol_entries") or [])]
        cdol1     = [e.get("tag", "") for e in (first.get("cdol1_entries") or [])]
        cdol2     = [e.get("tag", "") for e in (first.get("cdol2_entries") or [])]
        cvm_rules = first.get("cvm_rules") or []
        svc_code  = first.get("service_code")
        get_data  = first.get("get_data") or {}

        # Pull PIN retry and ATC from GET DATA (keys may have names appended)
        pin_retry = next(
            (v for k, v in get_data.items() if "9F17" in k and v), None
        )
        atc_now = next(
            (v for k, v in get_data.items() if "9F36" in k and v), None
        )

        existing = self._conn.execute(
            "SELECT first_seen_ts, times_seen, atc_first FROM cards WHERE fingerprint_hash=?",
            (h,),
        ).fetchone()

        if existing:
            atc_first = existing["atc_first"] or atc_now
            self._conn.execute(
                """UPDATE cards SET last_seen_ts=?, times_seen=times_seen+1,
                   aids_json=?, aip=?, aip_flags_json=?, pdol_tags_json=?,
                   cdol1_tags_json=?, cdol2_tags_json=?, cvm_rules_json=?,
                   service_code=?, pin_retry=?, atc_last=?, profile_json=?
                   WHERE fingerprint_hash=?""",
                (now, self._j(aids), aip, self._j(aip_flags), self._j(pdol_tags),
                 self._j(cdol1), self._j(cdol2), self._j(cvm_rules),
                 svc_code, pin_retry, atc_now, self._j(profile), h),
            )
        else:
            atc_first = atc_now
            self._conn.execute(
                """INSERT INTO cards
                   (fingerprint_hash, first_seen_ts, last_seen_ts, times_seen,
                    aids_json, aip, aip_flags_json, pdol_tags_json,
                    cdol1_tags_json, cdol2_tags_json, cvm_rules_json,
                    service_code, pin_retry, atc_first, atc_last, profile_json)
                   VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (h, now, now,
                 self._j(aids), aip, self._j(aip_flags), self._j(pdol_tags),
                 self._j(cdol1), self._j(cdol2), self._j(cvm_rules),
                 svc_code, pin_retry, atc_first, atc_now, self._j(profile)),
            )

        self._conn.commit()
        log.info("CardIntelDB: recorded card %s…", h[:12])
        return h

    # ── record_attack ─────────────────────────────────────────────────────────

    def record_attack(
        self,
        fingerprint_hash: str,
        attack_name: str,
        result: str,
        mutations_config: dict | None = None,
        mutations_fired: int = 0,
        mutation_log: list | None = None,
        session_log_file: str = "",
        notes: str = "",
    ) -> int:
        """
        Append an attack result. `result` should be one of:
        success | partial | failed | blocked | error
        Returns the new row id.
        """
        if result not in {"success", "partial", "failed", "blocked", "error"}:
            log.warning("CardIntelDB: unusual result value %r", result)

        now = int(time.time() * 1000)
        cur = self._conn.execute(
            """INSERT INTO attacks
               (fingerprint_hash, ts, attack_name, result, mutations_fired,
                mutations_config, mutation_log, session_log_file, notes)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (fingerprint_hash, now, attack_name, result, mutations_fired,
             self._j(mutations_config or {}), self._j(mutation_log or []),
             session_log_file, notes),
        )
        self._conn.commit()
        log.info(
            "CardIntelDB: recorded %s → %s (fired=%d) for %s…",
            attack_name, result, mutations_fired, fingerprint_hash[:12],
        )
        return cur.lastrowid

    # ── record_outcome ────────────────────────────────────────────────────────

    def record_outcome(
        self,
        label: str,
        fingerprint_hash: str = "",
        session_id: str = "",
        cmd_hex: str = "",
        cmd_ins: str = "",
        resp_hex: str = "",
        sw: str = "",
        notes: str = "",
        source: str = "auto",
    ) -> int:
        """
        Record one APDU-level mutation outcome.
        label: accepted | security_condition | interesting | manual_interesting
        source: auto (from WebSocketHandler) | manual (operator-flagged from UI)
        Returns the new row id.
        """
        now = int(time.time() * 1000)
        cur = self._conn.execute(
            """INSERT INTO mutation_outcomes
               (fingerprint_hash, session_id, ts, cmd_hex, cmd_ins,
                resp_hex, sw, label, notes, source)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (fingerprint_hash, session_id, now, cmd_hex, cmd_ins,
             resp_hex, sw, label, notes, source),
        )
        self._conn.commit()
        return cur.lastrowid

    # ── get_outcomes_summary ──────────────────────────────────────────────────

    def get_outcomes_summary(self, fingerprint_hash: str) -> dict:
        """
        Aggregate outcome counts for a specific card.
        Returns by_label counts and top SW patterns per INS.
        """
        rows = self._conn.execute(
            """SELECT label, sw, cmd_ins, COUNT(*) as n
               FROM mutation_outcomes
               WHERE fingerprint_hash=?
               GROUP BY label, sw, cmd_ins
               ORDER BY n DESC""",
            (fingerprint_hash,),
        ).fetchall()

        by_label: dict[str, int] = {}
        sw_patterns: list[dict] = []
        for row in rows:
            lbl = row["label"]
            by_label[lbl] = by_label.get(lbl, 0) + row["n"]
            sw_patterns.append({
                "label":   lbl,
                "sw":      row["sw"],
                "cmd_ins": row["cmd_ins"] or "",
                "count":   row["n"],
            })

        return {
            "total":       sum(by_label.values()),
            "by_label":    by_label,
            "sw_patterns": sw_patterns[:25],
        }

    # ── get_cross_card_patterns ───────────────────────────────────────────────

    def get_cross_card_patterns(self) -> dict:
        """
        Aggregate SW→label patterns across all cards.
        Useful for pre-session briefing: which mutations tend to trigger
        security conditions on similar cards.
        """
        rows = self._conn.execute(
            """SELECT label, sw, cmd_ins,
                      COUNT(*) as n,
                      COUNT(DISTINCT fingerprint_hash) as cards
               FROM mutation_outcomes
               GROUP BY label, sw, cmd_ins
               ORDER BY cards DESC, n DESC
               LIMIT 40""",
        ).fetchall()

        return {
            "patterns": [
                {
                    "label":   row["label"],
                    "sw":      row["sw"],
                    "cmd_ins": row["cmd_ins"] or "",
                    "count":   row["n"],
                    "cards":   row["cards"],
                }
                for row in rows
            ]
        }

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    # ── get_intel ─────────────────────────────────────────────────────────────

    def get_intel(self, fingerprint_hash: str) -> dict:
        """
        Return a full intel summary for a card — what the agent reads before
        deciding which attack to run next.

        Keys:
          known          : bool — card seen before
          card           : CardRecord dict (or None for new card)
          attack_history : list of AttackRecord dicts, newest first
          succeeded      : attack names with result "success"
          partial        : attack names with result "partial"
          failed         : attack names with result "failed" or "blocked"
          untried        : attacks not yet attempted
          recommended    : top-5 suggestions ordered by profile + history
        """
        row = self._conn.execute(
            "SELECT * FROM cards WHERE fingerprint_hash=?", (fingerprint_hash,)
        ).fetchone()

        if row is None:
            return {
                "known": False,
                "card": None,
                "attack_history": [],
                "succeeded": [], "partial": [], "failed": [],
                "untried": list(KNOWN_ATTACKS),
                "recommended": KNOWN_ATTACKS[:3],
            }

        card = CardRecord(
            fingerprint_hash=row["fingerprint_hash"],
            first_seen_ts=row["first_seen_ts"],
            last_seen_ts=row["last_seen_ts"],
            times_seen=row["times_seen"],
            aids=self._jl(row["aids_json"]),
            aip=row["aip"] or "",
            aip_flags=self._jl(row["aip_flags_json"]),
            pdol_tags=self._jl(row["pdol_tags_json"]),
            cdol1_tags=self._jl(row["cdol1_tags_json"]),
            cdol2_tags=self._jl(row["cdol2_tags_json"]),
            cvm_rules=self._jl(row["cvm_rules_json"]),
            service_code=row["service_code"],
            pin_retry=row["pin_retry"],
            atc_first=row["atc_first"],
            atc_last=row["atc_last"],
            notes=row["notes"] or "",
        )

        attack_rows = self._conn.execute(
            "SELECT * FROM attacks WHERE fingerprint_hash=? ORDER BY ts DESC",
            (fingerprint_hash,),
        ).fetchall()

        history = [
            AttackRecord(
                id=r["id"],
                fingerprint_hash=r["fingerprint_hash"],
                ts=r["ts"],
                attack_name=r["attack_name"],
                result=r["result"],
                mutations_fired=r["mutations_fired"],
                mutations_config=self._jd(r["mutations_config"]),
                mutation_log=self._jl(r["mutation_log"]),
                session_log_file=r["session_log_file"] or "",
                notes=r["notes"] or "",
            ).to_dict()
            for r in attack_rows
        ]

        tried    = {r["attack_name"] for r in attack_rows}
        succeeded = [r["attack_name"] for r in attack_rows if r["result"] == "success"]
        partial   = [r["attack_name"] for r in attack_rows if r["result"] == "partial"]
        failed    = [r["attack_name"] for r in attack_rows if r["result"] in ("failed", "blocked")]
        untried   = [a for a in KNOWN_ATTACKS if a not in tried]

        outcome_summary = self.get_outcomes_summary(fingerprint_hash)
        recommended = _recommend(card, succeeded, partial, failed, untried,
                                 outcomes=outcome_summary)

        return {
            "known": True,
            "card": card.to_dict(),
            "attack_history": history,
            "succeeded": succeeded, "partial": partial, "failed": failed,
            "untried": untried,
            "outcome_summary": outcome_summary,
            "recommended": recommended,
        }

    # ── list_cards ────────────────────────────────────────────────────────────

    def list_cards(self) -> list[dict]:
        """Summary row for every card, newest first."""
        rows = self._conn.execute(
            """SELECT fingerprint_hash, first_seen_ts, last_seen_ts, times_seen,
                      aids_json, aip, pin_retry, atc_first, atc_last, notes
               FROM cards ORDER BY last_seen_ts DESC"""
        ).fetchall()
        result = []
        for row in rows:
            h = row["fingerprint_hash"]
            counts = {
                r["result"]: r["n"]
                for r in self._conn.execute(
                    "SELECT result, COUNT(*) as n FROM attacks WHERE fingerprint_hash=? GROUP BY result",
                    (h,),
                ).fetchall()
            }
            result.append({
                "fingerprint_hash": h,
                "first_seen_ts": row["first_seen_ts"],
                "last_seen_ts":  row["last_seen_ts"],
                "times_seen":    row["times_seen"],
                "aids":  self._jl(row["aids_json"]),
                "aip":   row["aip"],
                "pin_retry":  row["pin_retry"],
                "atc_first":  row["atc_first"],
                "atc_last":   row["atc_last"],
                "notes":      row["notes"] or "",
                "attacks_run": counts,
            })
        return result

    # ── add_note ──────────────────────────────────────────────────────────────

    def add_note(self, fingerprint_hash: str, note: str) -> None:
        self._conn.execute(
            "UPDATE cards SET notes = notes || ? WHERE fingerprint_hash=?",
            (f"\n{note}", fingerprint_hash),
        )
        self._conn.commit()

    # ── delete_card ───────────────────────────────────────────────────────────

    def delete_card(self, fingerprint_hash: str) -> bool:
        """Delete a card and all its attack records. Returns True if found."""
        row = self._conn.execute(
            "SELECT fingerprint_hash FROM cards WHERE fingerprint_hash=?",
            (fingerprint_hash,),
        ).fetchone()
        if row is None:
            return False
        self._conn.execute("DELETE FROM attacks WHERE fingerprint_hash=?", (fingerprint_hash,))
        self._conn.execute("DELETE FROM cards WHERE fingerprint_hash=?", (fingerprint_hash,))
        self._conn.commit()
        log.info("CardIntelDB: deleted card %s… and its attacks", fingerprint_hash[:12])
        return True

    # ── delete_attack ─────────────────────────────────────────────────────────

    def delete_attack(self, attack_id: int) -> bool:
        """Delete a single attack record. Returns True if found."""
        row = self._conn.execute(
            "SELECT id FROM attacks WHERE id=?", (attack_id,),
        ).fetchone()
        if row is None:
            return False
        self._conn.execute("DELETE FROM attacks WHERE id=?", (attack_id,))
        self._conn.commit()
        log.info("CardIntelDB: deleted attack id=%d", attack_id)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Attack recommendation engine
# ─────────────────────────────────────────────────────────────────────────────

def _recommend(
    card: CardRecord,
    succeeded: list[str],
    partial: list[str],
    failed: list[str],
    untried: list[str],
    outcomes: dict | None = None,
) -> list[str]:
    """
    Ordered list of ≤5 recommended next attacks based on card profile + history
    + APDU-level mutation outcome patterns.
    Priority: partial retries > outcome-boosted > profile-matched > combo prerequisites > canonical.
    """
    seen: set[str] = set(succeeded) | set(failed)
    candidates: list[tuple[int, str]] = []

    def _add(priority: int, name: str) -> None:
        if name not in seen and name in KNOWN_ATTACKS:
            candidates.append((priority, name))

    # Partial attacks first (they showed some effect)
    for name in partial:
        if name not in seen:
            candidates.append((0, name))

    pdol      = set(card.pdol_tags)
    aip_byte1 = int(card.aip[:2], 16) if len(card.aip) >= 2 else 0

    # Outcome-pattern boosts: SW codes seen during prior sessions inform next attack
    if outcomes:
        sw_ins_pairs = {
            (p["sw"].upper(), (p.get("cmd_ins") or "").upper())
            for p in outcomes.get("sw_patterns", [])
        }
        sec_count = outcomes.get("by_label", {}).get("security_condition", 0)

        # 6985/6984 on GENERATE AC → card noticed CVM/crypto manipulation → downgrade first
        if any(sw in ("6985", "6984") and ins == "AE" for sw, ins in sw_ins_pairs):
            _add(3, "ATTACK-3")
            _add(3, "ATTACK-7")
        # 6985 on GPO → PDOL mutation was rejected → try TTQ manipulation instead
        if ("6985", "A8") in sw_ins_pairs:
            _add(3, "ATTACK-2")
        # Many security conditions → card is sensitive → silent collection first
        if sec_count >= 3:
            _add(2, "ATTACK-5")
        # 6983 (auth blocked) on VERIFY → PIN counter at 0 or blocked → no point in PIN
        if any(sw == "6983" and ins in ("20", "21") for sw, ins in sw_ins_pairs):
            _add(3, "ATTACK-4")   # force No-CVM since PIN path is blocked

    # Profile-matched untried
    if "9F02" in pdol:                       _add(10, "ATTACK-1")
    if "9F66" in pdol:                       _add(10, "ATTACK-2")
    if aip_byte1 & 0x21:                     _add(11, "ATTACK-3"); _add(11, "ATTACK-7")
    if card.cdol1_tags:                      _add(12, "ATTACK-8")
    if card.pin_retry not in ("00", "", None): _add(13, "ATTACK-5")
    if card.service_code:                    _add(20, "ATTACK-10")

    # Combo prerequisites met
    if "ATTACK-1" in succeeded:              _add(5, "COMBO-C")
    if set(succeeded) & {"ATTACK-3", "ATTACK-7"}: _add(6, "COMBO-B")

    # Fill with remaining untried
    for name in untried:
        _add(30, name)

    # Deduplicate preserving insertion order within each priority bucket
    seen_names: set[str] = set()
    result: list[str] = []
    for _, name in sorted(candidates):
        if name not in seen_names:
            seen_names.add(name)
            result.append(name)
    return result[:5]


# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI
# ─────────────────────────────────────────────────────────────────────────────

def _cli_main() -> None:
    import argparse, sys

    parser = argparse.ArgumentParser(description="card_intel – query the card intelligence DB")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="List all known cards")
    p_intel = sub.add_parser("intel", help="Show full intel for a card")
    p_intel.add_argument("hash", help="fingerprint_hash prefix")
    p_note = sub.add_parser("note", help="Append a note to a card")
    p_note.add_argument("hash")
    p_note.add_argument("text")
    args = parser.parse_args()

    db = CardIntelDB()

    if args.cmd == "list":
        cards = db.list_cards()
        if not cards:
            print("No cards in database.")
        for c in cards:
            print(
                f"\n{c['fingerprint_hash'][:16]}…  "
                f"seen={c['times_seen']}x  AIP={c['aip']}  "
                f"AIDs={c['aids']}  attacks={c['attacks_run']}"
            )

    elif args.cmd == "intel":
        match = [c for c in db.list_cards() if c["fingerprint_hash"].startswith(args.hash)]
        if not match:
            sys.exit(f"No card matching '{args.hash}'")
        print(json.dumps(db.get_intel(match[0]["fingerprint_hash"]), indent=2))

    elif args.cmd == "note":
        match = [c for c in db.list_cards() if c["fingerprint_hash"].startswith(args.hash)]
        if not match:
            sys.exit(f"No card matching '{args.hash}'")
        db.add_note(match[0]["fingerprint_hash"], args.text)
        print("Note added.")

    db.close()


if __name__ == "__main__":
    _cli_main()
