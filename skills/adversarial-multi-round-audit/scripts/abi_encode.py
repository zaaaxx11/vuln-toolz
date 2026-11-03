#!/usr/bin/env python3
"""ABI encoder for hand-built eth_call calldata — with the splice guards baked in.

WHY THIS EXISTS
  Hand-rolled ABI encoders silently splice a literal `0x` into the blob when any
  helper returns `0x`-prefixed hex (see references/abi-and-field-verification.md
  Rule 18). The resulting calldata is a plausible length and every probe then
  fails identically, reading as "the gate blocks everyone" or "wrong contract
  build". These helpers normalise once and assert, so that class cannot recur.

CONVENTION: every helper below returns BARE lowercase hex. Exactly one function
(`encode_with_struct`) prefixes `0x`, once, at the end.

USAGE
  from abi_encode import Sel, W, abi_bytes, encode_with_struct, assert_calldata

  sig = 'submitWithdrawRequest((string,bytes,bytes,uint256,string,bytes,bytes,bytes,bytes32))'
  data = encode_with_struct(
      sig,
      static_fields=[W(amount), W(int(nonce, 16))],      # uint256 / bytes32 -> W()
      dynamic_fields=[b'ton', bytes.fromhex(dep), b'\x00' * 32,
                      b'base', bytes.fromhex(spender), bytes.fromhex(receiver), b''],
  )
  assert_calldata(data)
  rpc('eth_call', [{'from': who, 'to': target, 'data': data}, 'latest'])
"""
from Crypto.Hash import keccak as _k


def keccak(b):
    h = _k.new(digest_bits=256)
    h.update(b if isinstance(b, bytes) else b.encode())
    return h.digest()


def Sel(sig):
    """4-byte selector, 0x-prefixed. Strip with [2:] when splicing."""
    return '0x' + keccak(sig)[:4].hex()


def W(n):
    """uint256/int-as-unsigned -> 64 bare hex chars. Accepts int or bare/0x hex str."""
    if isinstance(n, str):
        n = int(n, 16) if n.startswith('0x') else int(n, 16)
    if n < 0 or n >= 1 << 256:
        raise ValueError(f'word out of uint256 range: {n}')
    return format(n, '064x')


def abi_bytes(v):
    """ABI-encode a dynamic `bytes`/`string`: length word + right-padded data words.

    Returns BARE hex. len(v)==0 still emits W(0) with an empty tail — the old
    ljust-on-hex-length form silently produced a 1-char-short tail whenever
    len(v) % 32 == 0.
    """
    out = W(len(v))
    if v:
        h = v.hex()
        h += '0' * (((len(v) + 31) // 32) * 64 - len(h))
        out += h
    return out


def encode_with_struct(sig, static_fields, dynamic_fields):
    """Encode a call taking ONE tuple arg whose members are static, then dynamic.

    Head = len(static) + len(dynamic) words (dynamic members contribute an offset).
    Returns 0x-prefixed calldata.
    """
    n_head = len(static_fields) + len(dynamic_fields)
    cur = n_head * 32
    offsets, tails = [], []
    for v in dynamic_fields:
        offsets.append(cur)
        enc = abi_bytes(v)
        tails.append(enc)
        cur += len(enc) // 2          # bare hex -> chars/2 == bytes
    head = ''.join(static_fields) + ''.join(W(o) for o in offsets)
    body = Sel(sig)[2:] + W(32) + head + ''.join(tails)
    return '0x' + body


def assert_calldata(data, selector=True):
    """The two-line defence. Run this on EVERY hand-built call before sending."""
    assert data.startswith('0x'), 'calldata must be 0x-prefixed'
    body = data[2:]
    assert '0x' not in body, 'stray 0x prefix spliced inside blob (Rule 18)'
    assert 'x' not in body, 'non-hex character in calldata'
    assert all(c in '0123456789abcdef' for c in body), 'non-hex character in calldata'
    off = 8 if selector else 0
    assert (len(body) - off) % 64 == 0, (
        f'misaligned calldata: len={len(body)} selector={selector}')
    return True


if __name__ == '__main__':
    # self-test: a known-good round-trip
    s = 'balanceOf(address,uint256)'
    d = '0x' + Sel(s)[2:] + W(int('0xd5fa4f5834722d85d95f45387ed60ce09ba4e36f', 16)) + W(7)
    assert_calldata(d)
    assert len(d) == 2 + 8 + 128, len(d)
    assert abi_bytes(b'ton') == W(3) + '746f6e' + '0' * 58
    assert abi_bytes(b'') == W(0)
    print('abi_encode self-test OK')
    print('  sel', Sel(s))
