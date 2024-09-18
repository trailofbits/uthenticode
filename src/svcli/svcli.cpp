/**
 * \file svcli.cpp
 *
 * svcli: A small CLI demonstration of uthenticode's API.
 *
 * Usage: `svcli <exe>`
 */

#include <uthenticode.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

#include "vendor/argh.h"

#if __has_include(<unistd.h>)
#include <unistd.h>
#else
#include <fcntl.h>
#include <io.h>
#endif

static bool is_cout_a_pipe() {
#if __has_include(<unistd.h>)
  return !isatty(STDOUT_FILENO);
#else
  return !_isatty(_fileno(stdout));
#endif
}

using checksum_kind = uthenticode::checksum_kind;

int main(int argc, char const *argv[]) {
  argh::parser cmdl(argv);
  bool extract = false;

  if (cmdl[{"-v", "--version"}]) {
    std::cout << "svcli (uthenticode) version " << UTHENTICODE_VERSION << '\n';
    return 0;
  } else if (cmdl[{"-x", "--extract"}]) {
    extract = true;
  } else if (cmdl[{"-h", "--help"}] || argc != 2) {
    std::cout << "Usage: svcli [options] <file>\n\n"
              << "Options:\n"
              << "\t-v, --version\tPrint the version and exit\n"
              << "\t-x, --extract\tExtract the first certificate blob\n"
              << "\t-h, --help\tPrint this help message and exit\n\n"
              << "Arguments:\n"
              << "\t<input-file>\tThe PE to parse for Authenticode data\n"
              << "\t[output-file]\tWith -x/--extract the file to dump the buffer into (leave empty "
                 "or use - for stdout)\n";
    return 0;
  }
  auto const input_file = cmdl[1];
  auto *pe = peparse::ParsePEFromFile(input_file.c_str());
  if (pe == nullptr) {
    std::cerr << "pe-parse failure: " << input_file << ": " << peparse::GetPEErrString() << '\n';
    return 1;
  }

  if (!extract) {
    std::cout << "This PE is " << (uthenticode::verify(pe) ? "" : "NOT ") << "verified!\n\n";
  }

  const auto &certs = uthenticode::read_certs(pe);

  if (certs.empty()) {
    std::cerr << "PE has no certificate data!\n";
    return 1;
  }

  if (extract) {
    std::string fname;
    if (cmdl.size() > 1) {
      fname = cmdl[2];
    }
    if (!is_cout_a_pipe() && fname.empty()) {
      std::cerr
          << "Cowardly refusing to write binary data to TTY. Give '-' explicitly to force it.\n";
      return 1;
    }
    const bool want_stdout = fname.empty() || fname == "-";
    std::ofstream outfile;
    std::ostream *output;
    if (!want_stdout) {
      outfile.open(fname, std::ios::binary | std::ios::out);
      if (!outfile.is_open()) {
        std::cerr << "Failed to open '" << fname << "'.\n";
        return 1;
      }
      output = &outfile;
    } else {
      output = &std::cout;
    }
    for (const auto &cert : certs) {
      auto signed_data = cert.as_signed_data();
      if (!signed_data) {
        continue;
      }
      // dump first (valid) WinCert buffer
      auto const &raw_data = signed_data->get_raw_data();
      output->write(reinterpret_cast<const char *>(raw_data.data()), raw_data.size());
      return 0;
    }
  }

  std::cout << input_file << " has " << certs.size() << " certificate entries\n\n";

  std::cout << "Calculated checksums:\n";
  std::array<checksum_kind, 3> kinds = {
      checksum_kind::MD5, checksum_kind::SHA1, checksum_kind::SHA256};
  for (const auto &kind : kinds) {
    auto cksum = uthenticode::calculate_checksum(pe, kind);
    if (cksum.has_value()) {
      std::cout << std::setw(6) << kind << ": " << cksum.value() << '\n';
    } else {
      std::cout << std::setw(6) << kind << ": NONE (not signed)\n";
    }
  }
  std::cout << '\n';

  for (const auto &cert : certs) {
    const auto signed_data = cert.as_signed_data();
    if (!signed_data) {
      std::cerr << "Skipping non-SignedData entry\n";
      continue;
    }

    std::cout << "SignedData entry:\n"
              << "\tEmbedded checksum: " << std::get<std::string>(signed_data->get_checksum())
              << "\n\n";

    std::cout << "\tSigners:\n";
    for (const auto &signer : signed_data->get_signers()) {
      std::cout << "\t\tSubject: " << signer.get_subject() << '\n'
                << "\t\tIssuer: " << signer.get_issuer() << '\n'
                << "\t\tSerial: " << signer.get_serial_number() << '\n'
                << '\n';
    }

    std::cout << "\tCertificates:\n";
    for (const auto &cert : signed_data->get_certificates()) {
      std::cout << "\t\tSubject: " << cert.get_subject() << '\n'
                << "\t\tIssuer: " << cert.get_issuer() << '\n'
                << "\t\tSerial: " << cert.get_serial_number() << '\n'
                << '\n';
    }

    std::cout << "\tThis SignedData is " << (signed_data->verify_signature() ? "valid" : "invalid")
              << "!\n";

    const auto nested_signed_data = signed_data->get_nested_signed_data();
    if (!nested_signed_data) {
      continue;
    }

    std::cout << "\nNested SignedData entry:\n"
              << "\tEmbedded checksum: "
              << std::get<std::string>(nested_signed_data->get_checksum()) << "\n\n";

    std::cout << "\tSigners:\n";
    for (const auto &signer : nested_signed_data->get_signers()) {
      std::cout << "\t\tSubject: " << signer.get_subject() << '\n'
                << "\t\tIssuer: " << signer.get_issuer() << '\n'
                << "\t\tSerial: " << signer.get_serial_number() << '\n'
                << '\n';
    }

    std::cout << "\tCertificates:\n";
    for (const auto &cert : nested_signed_data->get_certificates()) {
      std::cout << "\t\tSubject: " << cert.get_subject() << '\n'
                << "\t\tIssuer: " << cert.get_issuer() << '\n'
                << "\t\tSerial: " << cert.get_serial_number() << '\n'
                << '\n';
    }

    std::cout << "\tThis SignedData is "
              << (nested_signed_data->verify_signature() ? "valid" : "invalid") << "!\n";
  }

  peparse::DestructParsedPE(pe);
  return 0;
}
