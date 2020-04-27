uthenticode
==========

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/uthenticode/CI/master)](https://github.com/trailofbits/uthenticode/actions?query=workflow%3ACI)

*uthenticode* (stylized as *μthenticode*) is a small cross-platform library for verifying
[Authenticode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
digital signatures.

## What?

Authenticode is Microsoft's code signing technology, designed to allow signing
and verification of programs.

*uthenticode* is a cross-platform reimplementation of the verification side of Authenticode.
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

*uthenticode* is **not** identical to the `Wintrust` API. Crucially, it **cannot** perform full-chain
verifications of Authenticode signatures, as it lacks access to the Trusted Publishers store.

You should use *uthenticode* to verify the embedded chain. You should **not** assume that a "verified"
binary from *uthenticode*'s perspective will run on an unmodified Windows system.

## Building

*uthenticode* depends on [pe-parse](https://github.com/trailofbits/pe-parse) and OpenSSL 1.1.0.

pe-parse (and OpenSSL, if you don't already have it) can be installed via `vcpkg`:

```bash
$ vcpkg install pe-parse
```

The rest of the build is standard CMake:

```bash
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```

If you have `doxygen` installed, you can build *uthenticode*'s documentation with the top-level
`Makefile`:

```bash
$ make doc
```

Pre-built (master) documentation is hosted [here](https://trailofbits.github.io/uthenticode/).

Similarly, you can build the (gtest-based) unit tests with `-DBUILD_TESTS=1`.

## Usage

*uthenticode*'s public API is documented in `uthenticode.h` and in the Doxygen documentation
(see above).

The `svcli` utility also provides a small example of using *uthenticode*'s APIs. You can build it
by passing `-DBUILD_SVCLI=1` to `cmake`:

```bash
$ cmake -DBUILD_SVCLI=1 ..
$ cmake --build .
$ ./src/svcli/svcli /path/to/some.exe
```

## Resources

The following resources were essential to *uthenticode*'s development:

* The [`osslsigncode`](https://sourceforge.net/projects/osslsigncode/) codebase
* ClamAV's [Authenticode documentation](https://www.clamav.net/documents/microsoft-authenticode-signature-verification)
* Microsoft's [Authenticode specification](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx) (circa 2008)
* Peter Gutmann's [Authenticode format notes](https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt)
* [RFC5652](https://tools.ietf.org/html/rfc5652)
