smolverify
==========

![CI](https://github.com/woodruffw/smolverify/workflows/CI/badge.svg)

A ˢᵐᵒˡ (small) cross-platform library for verifying
[Authenticode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
digital signatures.

## What?

Authenticode is Microsoft's code signing technology, designed to allow signing
and verification of programs.

*smolverify* is a cross-platform reimplementation of the verification side of Authenticode.
It doesn't attempt to provide the signing side.

## Why?

Because the official APIs (namely, the `Wintrust` API) for interacting with Authenticode signatures
are baked deeply into Windows, making it difficult to verify signed Windows executables on
non-Windows hosts.

Other available solutions are deficient:

* WINE implements most of `Wintrust`, but is a massive (and arguably non-native) dependency
for a single task.
* [`osslsigncode`](https://sourceforge.net/projects/osslsigncode/) can add signatures and check
timestamps, but is long-abandoned and CLI-focused.

## Beware!

*smolverify* is **not** identical to the `Wintrust` API. Crucially, it **cannot** perform full-chain
verifications of Authenticode signatures, as it lacks access to the Trusted Publishers store.

You should use *smolverify* to verify the embedded chain. You should **not** assume that a "verified"
binary from *smolverify*'s perspective will run on an unmodified Windows system.

## Building

*smolverify* depends on [pe-parse](https://github.com/trailofbits/pe-parse) and OpenSSL 1.1.0.

```bash
$ mkdir build && cd build
$ cmake ..
$ make
```

If you have `doxygen` installed, you can build *smolverify*'s documentation
with `-DBUILD_DOCUMENTATION=1`:

```bash
$ cmake -DBUILD_DOCUMENTATION=1 ..
$ make doc
```

## Usage

*smolverify*'s public API is documented in `smolverify.h` and in the Doxygen documentation
(see above).

The `svcli` utility also provides a small example of using *smolverify*'s APIs. You can build it
by passing `-DBUILD_SVCLI=1` to `cmake`:

```bash
$ cmake -DBUILD_SVCLI=1 ..
$ make
$ ./src/svcli/svcli /path/to/some.exe
```

## Resources

The following resources were essential to *smolverify*'s development:

* The [`osslsigncode`](https://sourceforge.net/projects/osslsigncode/) codebase
* ClamAV's [Authenticode documentation](https://www.clamav.net/documents/microsoft-authenticode-signature-verification)
* Microsoft's [Authenticode specification](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx) (circa 2008)
* Peter Gutmann's [Authenticode format notes](https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt)
* [RFC5652](https://tools.ietf.org/html/rfc5652)
