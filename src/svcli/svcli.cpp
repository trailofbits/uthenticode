/**
 * \file svcli.cpp
 *
 * svcli: A small CLI demonstration of smolverify's API.
 *
 * Usage: `svcli <exe>`
 */

#include <smolverify.h>

#include <array>
#include <iomanip>
#include <iostream>

using checksum_kind = smolverify::checksum_kind;

int main(int argc, char const *argv[]) {
  if (argc != 2) {
    return 1;
  }

  auto *parsed_pe = peparse::ParsePEFromFile(argv[1]);
  if (parsed_pe == nullptr) {
    std::cerr << "pe-parse failure: " << peparse::GetPEErrString() << '\n';
    return 1;
  }

  const auto &certs = smolverify::read_certs(parsed_pe);

  if (certs.empty()) {
    std::cerr << "PE has no certificate data!\n";
    return 1;
  }

  std::cout << argv[1] << " has " << certs.size() << " certificate entries\n\n";

  std::cout << "Calculated checksums:\n";
  std::array<smolverify::checksum_kind, 3> kinds = {
      checksum_kind::MD5, checksum_kind::SHA1, checksum_kind::SHA256};
  for (const auto &kind : kinds) {
    std::cout << std::setw(6) << kind << ": " << smolverify::calculate_checksum(parsed_pe, kind)
              << '\n';
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
  }

  peparse::DestructParsedPE(parsed_pe);
}
