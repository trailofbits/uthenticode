/**
 * \file svcli.cpp
 *
 * svcli: A small CLI demonstration of uthenticode's API.
 *
 * Usage: `svcli <exe>`
 */

#include <uthenticode.h>

#include <array>
#include <iomanip>
#include <iostream>

#include "vendor/argh.h"

using checksum_kind = uthenticode::checksum_kind;

int main(int argc, char const *argv[]) {
  argh::parser cmdl(argv);

  if (cmdl[{"-v", "--version"}]) {
    std::cout << "svcli (uthenticode) version " << UTHENTICODE_VERSION << '\n';
    return 0;
  } else if (cmdl[{"-h", "--help"}] || argc != 2) {
    std::cout << "Usage: svcli [options] <file>\n\n"
              << "Options:\n"
              << "\t-v, --version\tPrint the version and exit\n"
              << "\t-h, --help\tPrint this help message and exit\n\n"
              << "Arguments:\n"
              << "\t<file>\tThe PE to parse for Authenticode data\n";
    return 0;
  }

  auto *pe = peparse::ParsePEFromFile(cmdl[1].c_str());
  if (pe == nullptr) {
    std::cerr << "pe-parse failure: " << cmdl[1] << ": " << peparse::GetPEErrString() << '\n';
    return 1;
  }

  std::cout << "This PE is " << (uthenticode::verify(pe) ? "" : "NOT ") << "verified!\n\n";

  const auto &certs = uthenticode::read_certs(pe);

  if (certs.empty()) {
    std::cerr << "PE has no certificate data!\n";
    return 1;
  }

  std::cout << cmdl[1] << " has " << certs.size() << " certificate entries\n\n";

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
}
