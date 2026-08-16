# ALLVM hardening notes

This branch starts the hardening work with changes that are small enough to
review and validate independently.

## Secure build-time randomization

The constant-integer and constant-floating-point passes now seed their local
`CryptoUtils` instances through the operating system CSPRNG:

- Windows: CNG `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
- Linux and other POSIX hosts: `/dev/urandom`, including partial-read and
  interrupted-system-call handling.

A 32-byte build root is generated once and SHA-256 domain separation derives a
different 128-bit AES-CTR seed for each pass. This avoids the previous pattern
of independent time-seeded generators and prevents accidental seed reuse
between the integer and floating-point passes.

For an explicitly reproducible build, set `ALLVM_BUILD_SEED` to exactly 64
hexadecimal characters (an optional `0x` prefix is accepted):

```bash
export ALLVM_BUILD_SEED=9f3d0f0f2a37d64e7adbb5bf402f8de02ecdf73334edb81beeaaf9d6f2aaf02c
```

Do not use a human-readable password as this value. Leaving the variable unset
is the recommended production mode.

## Environment diagnostics

Run the standard-library-only doctor before building:

```bash
python3 tools/allvm-doctor.py --ndk /path/to/android-ndk
```

The command discovers CMake, Ninja, Java, ADB, the NDK host toolchain, and its
Clang/lld binaries without modifying the NDK.

To inspect an Android ELF for 16 KiB LOAD-segment alignment:

```bash
python3 tools/allvm-doctor.py --ndk /path/to/android-ndk --elf libexample.so
```

Machine-readable output is available with `--json`.

## Correctness fixes included

Both constant-encryption passes now:

- test the current function's collected instruction set rather than the global
  map when deciding whether there is work to do;
- use PHI incoming-value APIs consistently during collection and rewriting;
- preserve the existing skip behavior for PHI predecessors terminated by a
  switch.

## Deliberately deferred

The legacy VMP implementation and the default `CryptoUtils::prng_seed()` path
are intentionally deferred to separate commits because those files are large
and security-sensitive. They should be changed with dedicated regression tests
rather than mixed into this first patch.
