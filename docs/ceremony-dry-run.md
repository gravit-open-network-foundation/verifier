# Root key ceremony — dry run

Goal: before buying five devices, prove with **one** device that it produces
the plain Ed25519 signatures the kernel accepts. Procedure context:
`root-key-custody.md` §4. Tool: `tools/ceremony.py`.

## What "plain Ed25519" means

The kernel checks a 64-byte Ed25519 signature over the exact bytes it is
given. Many tokens sign in OpenPGP or CMS format instead (they add headers or
sign a hash). Such signatures are **not** accepted. The dry run finds this
out before anyone depends on the device.

## Steps (about 30 minutes, one holder + one maintainer)

1. **Maintainer** runs `python tools/ceremony.py selftest` to confirm the tool
   works (all three lines `True`).
2. **Maintainer** creates the challenge:
   `python tools/ceremony.py challenge --holder "<name>" --date <YYYY-MM-DD> --out challenge.bin`
   and reads the printed SHA-256 to the holder by phone.
3. **Holder**, on their own computer with the device:
   - generates an Ed25519 key **on the device** (it must not be exportable);
   - exports the **public** key (PEM is fine);
   - checks the SHA-256 of `challenge.bin` matches what was read out;
   - signs `challenge.bin` with plain Ed25519 and saves the signature
     (64-byte binary file, or base64).
4. **Holder** sends `pub.pem` and the signature to the maintainer. Never the
   private key — there is no step where it leaves the device.
5. **Maintainer** runs
   `python tools/ceremony.py verify --holder "<name>" --date <YYYY-MM-DD> --public-key pub.pem --signature sig.bin`.
   - `OK` → the device works; the printed entry is what goes into
     `trust_root.json` and `ROOT_KEYS.md` at the real ceremony.
   - `FAIL` or "must be exactly 64 bytes" → the device or its software does
     not produce plain Ed25519; try another signing mode or another device.
6. Throw away the dry-run key's entry. Real keys are generated only at the
   ceremony itself, with every holder present or on a call.

## Result to record

Device model, firmware, signing command used, and OK/FAIL — in the pull
request that schedules the ceremony.
