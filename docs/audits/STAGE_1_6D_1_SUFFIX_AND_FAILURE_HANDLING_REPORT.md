# Stage 1.6D-1 — Sender Suffix Parsing and Registry Failure Handling

**Result: PASS WITH CONDITIONS**
- Both fixes are implemented and unit-tested.
- The conditions are in section 6: suffix evidence is partly external, and integration tests could not be run.

## 1. Root causes
- **F1:** `parse_sender_id` split on the first hyphen and kept everything after it as the header. `VM-SBIBNK-S` therefore looked up `SBIBNK-S`. The registry stores base headers only, and none contains a hyphen, so these senders returned `UNREGISTERED` (+20 risk and a spoofing warning).
- **F3:** `analyze_message` called `validate_sender` with no error handling. Any registry or database exception propagated as HTTP 500, discarding the pattern analysis that had already completed. After a failed query the session was also left in a failed state.

## 2. Files changed
- `app/services/sms_header_validator.py`:
  - `parse_sender_id` and a supported-suffix rule
  - `lookup_status` and `sender_suffix` on every result
  - new `registry_unavailable_result` and `validate_sender_safe`
- `app/routers/message_analyzer.py`:
  - uses `validate_sender_safe` in `/analyze` and `/validate-sender`
  - `SenderValidation` gained two optional fields
  - alert-write tolerance and logger
  - (the diff against Git also includes earlier uncommitted work in this file)
- New: `tests/unit/test_sender_suffix_and_registry_failure.py` (40 tests).
- New: this report.

Not changed: scoring constants, `scam_verdict_adapters.py`, the verdict schema, migrations, registry data, Flutter.

## 3. Normalisation rules implemented
A sender is rewritten **only** when the whole trimmed string matches `[A-Za-z]{2}-[A-Za-z0-9]+-[STPstp]` (ASCII only).
- The base header is looked up. The prefix letters give the TSP and LSA codes, as before.
- The suffix is reported in `sender_suffix`.
- `sender_id` keeps the original, upper-cased sender for evidence.
- The registered detail text adds "(category suffix -S)".

Never rewritten, and so looked up unchanged:
- unknown letters (`-X`), `-G`, multi-letter or empty suffixes (`-SS`, `-`), a second suffix (`-S-S`);
- a prefix of other than two letters, and headers with spaces;
- any non-ASCII look-alike, in the prefix, header or suffix, including Cyrillic `С` and the long s `ſ`, which `upper()` would turn into `S`.

Unsuffixed senders, bare headers, lower case, and phone numbers behave exactly as before. A suffixed sender whose base header is not registered stays `UNREGISTERED`.

## 4. Evidence for the supported suffixes
- The request names exactly `-S`, `-T` and `-P` (`VM-SBIBNK-S`, `VM-SBIBNK-T`, `AD-HDFCBK-P`). The local registry shows the base headers `SBIBNK` and `HDFCBK` exist and that no registry header carries a suffix. Live read-only lookups against the seeded local registry confirm those three now resolve to REGISTERED.
- **The project contains no written evidence of the suffix scheme.** The bundled TRAI PDF (`Detail_Header_Prefixes_16062020_0.pdf`) has CID-encoded text that my tools could not read, and a search of the repo docs found nothing. The three letters rest on the request plus the TRAI category convention (Service, Transactional, Promotional). A person should confirm them against the TRAI source.
- **`-G` (government) is deliberately not supported** until verified. A `-G` sender still returns `UNREGISTERED` as before.

## 5. Registry failure behaviour
`validate_sender_safe` wraps the lookup with a 3-second timeout (`REGISTRY_LOOKUP_TIMEOUT_SECONDS`). On any `Exception` (connection error, missing table, timeout, unexpected error) it:
- rolls back the session so it can be reused;
- returns `UNKNOWN`, `is_registered=None`, `lookup_status="unavailable"`, with the text "could not be checked… says nothing about whether the sender is genuine";
- logs only a warning with the exception **class** — no sender, message text, host or credentials (tested with sentinel secrets);
- does **not** swallow `CancelledError`.

In `/analyze`:
- The pattern analysis and score are unchanged, and no registry red flag or `sender_not_registered` evidence is produced.
- The shared verdict reports the existing limitation "The sender could not be verified against the registry." Its risk score equals the no-sender baseline.
- The alert write may fail without losing the response **only while the registry is down**. With a healthy registry an alert failure still raises (tested).
- `lookup_status` (`ok`, `unavailable`, `not_applicable`) distinguishes an outage from `UNREGISTERED`.
- Other failures in the analysis (pattern engine, verdict building) are not caught.

## 6. Tests and results
- **Unit tests** (executed, in-memory fakes, no database):
  - 40 new tests: suffix parsing (all required cases), lookup by base header, original preserved, unknown suffixes, malformed and look-alike strings, phone numbers, DB-unavailable, timeout, unexpected error, slow-query timeout, cancellation, pattern analysis surviving, UNKNOWN status and explanation, normal REGISTERED, UNREGISTERED (+20) and PHONE_NUMBER (+10) outcomes unchanged, and registered-is-not-safe.
  - Full unit suite: **1445 passed, 3 skipped, 0 failed**. The connection guard recorded 0 attempts by tests.
  - Ruff `--select F,E9`: clean on the changed files.
  - The existing shared-verdict tests and the scam-verdict adapter tests pass in that run.
- **Integration tests: not run.** They need a separate test database. The existing router test file was not executed in this stage.
- **Read-only live check** against local `secureshield_dev` (not a test): `VM-SBIBNK-S`, `-T`, `AD-HDFCBK-P` and `vm-sbibnk-s` are REGISTERED. `-X`, `-G` and an unregistered base header are UNREGISTERED. The registry is still 11 / 22 / 23,192. No writes.

## 7. Remaining limitations
- The `-S/-T/-P` evidence is the request plus convention, and `-G` is not supported (above).
- `+91…-S`-style strings are not treated as phone numbers (existing behaviour).
- The registry timeout of 3 s is a judgement and not configurable.
- Alert previews still store sender and 100 message characters (audit finding F2) and Flutter still hides the verdict limitations. Both are outside this stage.

## 8. Boundaries
No Neon or production access, no migrations, no reseed, no registry writes, no FastAPI startup, no AI or provider activation, no Flutter change, no commit or push.
