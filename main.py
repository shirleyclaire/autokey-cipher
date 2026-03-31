"""
main.py
-------
Demonstrates the full MAC-with-Autokey authentication flow with clear,
labelled console output.

Scenarios covered:
  1. Normal flow          – message arrives intact → authenticated ✓
  2. Tampered message     – attacker changes message body → rejected ✗
  3. Wrong keyword        – receiver uses wrong key → rejected ✗
  4. Different messages   – shows hash sensitivity (avalanche effect)
"""

from mac_protocol import create_payload, verify_payload
from hash_engine  import custom_hash

# ── pretty-print helpers ────────────────────────────────────────────────────────

LINE = "─" * 62

def section(title: str) -> None:
    print(f"\n{'═' * 62}")
    print(f"  {title}")
    print('═' * 62)

def sub(label: str, value: str) -> None:
    print(f"  {label:<26} {value}")

def result(ok: bool) -> None:
    tag = "✓  AUTHENTIC" if ok else "✗  TAMPERED / REJECTED"
    print(f"\n  {'Result:':<26} {tag}")
    print(LINE)


# ── scenario 1: happy path ──────────────────────────────────────────────────────

section("SCENARIO 1 – Normal transmission (message arrives intact)")

MESSAGE  = "Hello from the sender!"
KEYWORD  = "SECRET"

print(f"\n  [SENDER]")
sub("Original message:",  MESSAGE)
sub("Secret keyword:",    KEYWORD)

hash_digest    = custom_hash(MESSAGE)
sub("Hash digest (H):",   hash_digest)

payload = create_payload(MESSAGE, KEYWORD)
parts   = payload.split("||")

sub("Encrypted hash E(H):", parts[1])
sub("Transmitted payload:", payload)

print(f"\n  [RECEIVER]")
outcome = verify_payload(payload, KEYWORD)
sub("Decrypted hash H':",  outcome["received_hash"])
sub("Recomputed hash H:",  outcome["computed_hash"])
sub("Hashes match?",       str(outcome["received_hash"] == outcome["computed_hash"]))
result(outcome["is_authentic"])


# ── scenario 2: tampered message ───────────────────────────────────────────────

section("SCENARIO 2 – Tampered message (attacker modifies body)")

TAMPERED_MESSAGE = "Hello from the ATTACKER!"

print(f"\n  [SENDER sends original payload]")
original_payload = create_payload(MESSAGE, KEYWORD)
sub("Original payload:", original_payload)

print(f"\n  [ATTACKER replaces message portion]")
_, encrypted_hash_tag = original_payload.split("||", 1)
tampered_payload = f"{TAMPERED_MESSAGE}||{encrypted_hash_tag}"
sub("Tampered payload:", tampered_payload)

print(f"\n  [RECEIVER]")
outcome = verify_payload(tampered_payload, KEYWORD)
sub("Decrypted hash H':",  outcome["received_hash"])
sub("Recomputed hash H:",  outcome["computed_hash"])
sub("Hashes match?",       str(outcome["received_hash"] == outcome["computed_hash"]))
result(outcome["is_authentic"])


# ── scenario 3: wrong keyword ───────────────────────────────────────────────────

section("SCENARIO 3 – Wrong keyword at receiver")

WRONG_KEYWORD = "GUESS"

print(f"\n  [SENDER uses correct keyword: {KEYWORD!r}]")
payload = create_payload(MESSAGE, KEYWORD)
sub("Transmitted payload:", payload)

print(f"\n  [RECEIVER uses wrong keyword: {WRONG_KEYWORD!r}]")
outcome = verify_payload(payload, WRONG_KEYWORD)
sub("Decrypted hash H':",  outcome["received_hash"])
sub("Recomputed hash H:",  outcome["computed_hash"])
sub("Hashes match?",       str(outcome["received_hash"] == outcome["computed_hash"]))
result(outcome["is_authentic"])


# ── scenario 4: hash sensitivity / avalanche effect ────────────────────────────

section("SCENARIO 4 – Hash sensitivity (avalanche effect)")

messages = [
    "Hello from the sender!",
    "Hello from the sender.",   # only last char differs
    "hello from the sender!",   # only capitalisation differs
    "Hello from the Sender!",   # one capital letter changed
]

print(f"\n  {'Message':<38} {'Hash'}")
print(f"  {LINE}")
for msg in messages:
    h = custom_hash(msg)
    print(f"  {msg!r:<38} {h}")
print()
