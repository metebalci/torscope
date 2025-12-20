# HSDir Selection - RESOLVED

## Problem
The `hidden-service` command was getting 404 errors from HSDirs because we were selecting wrong HSDirs.

## Root Causes (3 bugs found)

### Bug 1: Wrong SRV for hsdir_index
- **Issue**: Used `shared_rand_previous` for hsdir_index computation
- **Fix**: Use `shared_rand_current` (`use_second_srv=False` in `cli.py:985`)

### Bug 2: Cache not storing Ed25519 identities
- **Issue**: `save_microdescriptors()` didn't save `ed25519_identity`
- **Fix**: Added `ed25519_identity` to cache save/load in `cache.py`

### Bug 3: Wrong hs_index computation (replica size)
- **Issue**: Used 1 byte for replica (`struct.pack("B", replica)`)
- **Fix**: Use 8 bytes (`struct.pack(">Q", replica)`) - INT_8 means 8 bytes!
- **Location**: `hsdir.py:_compute_hs_index()`

## Verification
```
$ torscope hidden-service duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion

Responsible HSDirs (6):
  [1] catpain
  [2] diana
  [3] bigdaddykane
  ... and 3 more

Fetching descriptor from wintrymix...
  Descriptor fetched from wintrymix ✓
```

## Key Formulas (Empirically Verified)

**hsdir_index** (where each HSDir sits on the ring):
```
hsdir_index = SHA3-256("node-idx" | ed25519_id | SRV_CURRENT | INT_8(period_num) | INT_8(period_length))
```

**hs_index** (where the service descriptor should be stored):
```
hs_index = SHA3-256("store-at-idx" | blinded_key | INT_8(replica) | INT_8(period_length) | INT_8(period_num))
```

Note:
- INT_8 = 8 bytes (64-bit big-endian integer)
- The blinded key derivation does NOT use SRV - only the time period
- For hsdir_index, use `shared_rand_current` from the consensus
