# uthenticode

[![Tests](https://github.com/trailofbits/uthenticode/actions/workflows/tests.yml/badge.svg)](https://github.com/trailofbits/uthenticode/actions/workflows/tests.yml)

*uthenticode* (stylized as *μthenticode*) is a small cross-platform library for
partially verifying [Authenticode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
digital signatures.

> [!WARNING]\
> This is not a full implementation of Authenticode; you **must not** use it in a way that assumes
> that its results are equivalent to verification on a Windows machine. See the [caveats](#caveats)
> below for more details.

[Read our blog post on verifying Windows binaries without Windows!](https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/)

## What?

Authenticode is Microsoft's code signing technology, designed to allow signing
and verification of programs.

*μthenticode* is a cross-platform reimplementation of the verification side of
Authenticode. It doesn't attempt to provide the signing side.

## Why?

Because the official APIs (namely, the `Wintrust` API) for interacting with
Authenticode signatures are baked deeply into Windows, making it difficult to
verify signed Windows executables on non-Windows hosts.

Other available solutions are deficient:

* WINE implements most of `Wintrust`, but is a massive (and arguably non-native)
  dependency for a single task.
* [`osslsigncode`](https://github.com/mtrojnar/osslsigncode) can add signatures
  and check timestamps, but is CLI-focused.

## Caveats

*μthenticode* is **not** identical to the `Wintrust` API. Crucially, it
**cannot** perform full-chain verifications of Authenticode signatures, as it
lacks access to the Trusted Publishers store.

You can use *μthenticode* to cryptographically verify the embedded chain.
You **must not** assume that a "verified" binary from *μthenticode*'s
perspective will run on an unmodified Windows system. We make no claim that
*μthenticode*'s implementation of the Authenticode certificate policy is
complete.

## Building

*μthenticode* depends on [pe-parse](https://github.com/trailofbits/pe-parse)
and OpenSSL 3.0 or higher, which are installed via `vcpkg` by following these steps:

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<vcpkg-path>/scripts/buildsystems/vcpkg.cmake
cmake --build build
# the default install prefix is the build directory;
# use CMAKE_INSTALL_PREFIX to modify it
cmake --build build --target install
```

If you have `doxygen` installed, you can build *μthenticode*'s documentation
with the top-level `Makefile`:

```bash
make doc
```

Pre-built (master) documentation is hosted
[here](https://trailofbits.github.io/uthenticode/).

You can build the (gtest-based) unit tests with `-DBUILD_TESTS=1`.

## Usage

*μthenticode*'s public API is documented in `uthenticode.h` and in the Doxygen
documentation (see above).

The `svcli` utility also provides a small example of using *μthenticode*'s APIs.
You can build it by passing `-DBUILD_SVCLI=1` to `cmake`:

```bash
cmake -DBUILD_SVCLI=1 -B build -S . -DCMAKE_TOOLCHAIN_FILE=<vcpkg-path>/scripts/buildsystems/vcpkg.cmake
cmake --build build
./build/src/svcli/svcli /path/to/some.exe
```

## Resources

The following resources were essential to *uthenticode*'s development:

* The [`osslsigncode`](https://github.com/mtrojnar/osslsigncode) codebase
* ClamAV's [Authenticode documentation](https://www.clamav.net/documents/microsoft-authenticode-signature-verification)
* Microsoft's
  [Authenticode specification](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
  (circa 2008)
* Peter Gutmann's [Authenticode format notes](https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt)
* [RFC5652](https://tools.ietf.org/html/rfc5652)
