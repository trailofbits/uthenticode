#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <parser-library/parse.h>

#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <vector>

/**
 * \file uthenticode.h
 *
 * The main uthenticode namespace.
 */
namespace uthenticode {

/**
 * This namespace is intentionally undocumented.
 */
namespace impl {
typedef struct {
  ASN1_OBJECT *type;
  ASN1_TYPE *value;
} Authenticode_SpcAttributeTypeAndOptionalValue;

typedef struct {
  X509_ALGOR *digestAlgorithm;
  ASN1_OCTET_STRING *digest;
} Authenticode_DigestInfo;

typedef struct {
  Authenticode_SpcAttributeTypeAndOptionalValue *data;
  Authenticode_DigestInfo *messageDigest;
} Authenticode_SpcIndirectDataContent;

/* Custom ASN.1 insanity is quarantined to the impl namespace.
 */
DECLARE_ASN1_FUNCTIONS(Authenticode_SpcAttributeTypeAndOptionalValue)
DECLARE_ASN1_FUNCTIONS(Authenticode_DigestInfo)
DECLARE_ASN1_FUNCTIONS(Authenticode_SpcIndirectDataContent)

/* OpenSSL defines OPENSSL_free as a macro, which we can't use with decltype.
 * So we wrap it here for use with unique_ptr.
 */
void OpenSSL_free(void *ptr);

/* Convenient self-releasing aliases for libcrypto and custom ASN.1 types.
 */
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using ASN1_OBJECT_ptr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using OpenSSL_ptr = std::unique_ptr<char, decltype(&OpenSSL_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)>;

using SectionList = std::vector<const peparse::bounded_buffer *>;

constexpr auto SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4";
}  // namespace impl

/**
 * The certificate revision.
 * This value has nothing to do with the structure or format of the certificate,
 * and is completely useless as far as I can tell.
 *
 * MSDN lies and says that CERT_REVISION_1_0 is the only defined revision;
 * every binary that I've seen uses CERT_REVISION_2_0.
 */
enum class certificate_revision : std::uint16_t {
  CERT_REVISION_1_0 = 0x0100, /**< Revision 1.0 of the WIN_CERT structure (supposedly) */
  CERT_REVISION_2_0 = 0x0200, /**< Revision 2.0 of the WIN_CERT structure */
};

/**
 * The kind of embedded certificate data.
 *
 * This library only supports verifying CERT_TYPE_PKCS_SIGNED_DATA, since that's
 * what Authenticode uses.
 */
enum class certificate_type : std::uint16_t {
  CERT_TYPE_X509 = 0x0001,             /**< An x509 certificate */
  CERT_TYPE_PKCS_SIGNED_DATA = 0x0002, /**< A PKCS#7 SignedData */
  CERT_TYPE_RESERVED_1 = 0x0003,       /**< Reserved by Windows. */
  CERT_TYPE_PKCS1_SIGN = 0x0009,       /**< PKCS1_MODULE_SIGN fields */
};

/**
 * An enumeration for supported checksum algorithms.
 */
enum class checksum_kind : std::uint8_t {
  UNKNOWN, /**< An unknown checksum kind */
  MD5,     /**< MD5 */
  SHA1,    /**< SHA-1 */
  SHA256,  /**< SHA2-256 */
};

std::ostream &operator<<(std::ostream &os, checksum_kind kind);

/**
 * A convenience union for representing the kind of checksum returned, as
 * well as its actual digest data.
 */
using Checksum = std::tuple<checksum_kind, std::string>;

/**
 * Raised on SignedData instantiation in the event of malformed PKCS#7 data.
 */
struct FormatError : public std::runtime_error {
 public:
  FormatError(const char *msg) : std::runtime_error(msg) {
  }
};

/**
 * Exposes some details of an X.509 certificate or signature.
 *
 * This is *not* a general-purpose accessor for an underlying OpenSSL
 * object; it only exposes a few select fields for public consumption.
 */
class Certificate {
 public:
  friend class SignedData;

  /**
   * @return the certificate subject
   */
  const std::string &get_subject() const {
    return subject_;
  }

  /**
   * @return the certificate issuer
   */
  const std::string &get_issuer() const {
    return issuer_;
  }

  /**
   * @return the certificate's serial number, formatted as a hex string
   */
  const std::string &get_serial_number() const {
    return serial_number_;
  }

  /* TODO: Maybe add data_ and get_data(), with data_ populated from i2d_X509.
   */

 private:
  Certificate(X509 *cert);
  std::string subject_;
  std::string issuer_;
  std::string serial_number_;
};

/**
 * Encapsulates an Authenticode PKCS#7 SignedData blob.
 */
class SignedData {
 public:
  /**
   * Create a SignedData from the given raw buffer.
   *
   * @throw FormatError if the buffer is not a Authenticode PKCS#7 SignedData
   */
  SignedData(std::vector<std::uint8_t> cert_buf);
  SignedData(SignedData &&s) noexcept;
  SignedData(const SignedData &) = delete;
  ~SignedData();

  /**
   * Verifies the Authenticode signature.
   *
   * @return true if valid, false otherwise
   */
  bool verify_signature() const;

  /**
   * Returns the kind of checksum in this SignedData and its contents.
   *
   * @return a Checksum tuple
   */
  Checksum get_checksum() const;

  /**
   * Returns the list of signer certificates in this SignedData.
   *
   * @return a list of Certificate instances
   */
  std::vector<Certificate> get_signers() const;

  /**
   * Returns the list of verification certificates in this SignedData.
   *
   * @return a list of Certificate instances
   */
  std::vector<Certificate> get_certificates() const;

 private:
  impl::Authenticode_SpcIndirectDataContent *get_indirect_data() const;

  std::vector<std::uint8_t> cert_buf_;
  PKCS7 *p7_{nullptr};
  impl::Authenticode_SpcIndirectDataContent *indirect_data_{nullptr};
};

/**
 * Encapsulates the data in a
 * [`WIN_CERT`](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate)
 * structure.
 *
 * `WIN_CERT` structures can contain several different underlying container formats;
 * this class provides accessors (like as_signed_data()) for retrieving supported ones.
 */
class WinCert {
 public:
  WinCert(certificate_revision revision, certificate_type type, std::vector<std::uint8_t> cert_buf)
      : revision_(revision), type_(type), cert_buf_(cert_buf) {
  }

  /**
   * @return the length of the underlying certificate data
   */
  std::size_t get_length() const {
    return cert_buf_.size();
  }

  /**
   * @return the revision of the structure
   */
  certificate_revision get_revision() const {
    return revision_;
  }

  /**
   * @return the type of data in the structure
   */
  certificate_type get_type() const {
    return type_;
  }

  /**
   * @return this object as a SignedData, or `std::nullopt` if the underlying data is not a
   * SignedData
   */
  std::optional<SignedData> as_signed_data() const;

 private:
  certificate_revision revision_;
  certificate_type type_;
  std::vector<std::uint8_t> cert_buf_;
};

/**
 * Parses the certificates from the given `parsed_pe`.
 *
 * @param pe the `peparse::parsed_pe` to extract certificates from
 * @return a vector of uthenticode::WinCert
 */
std::vector<WinCert> read_certs(peparse::parsed_pe *pe);

/**
 * Returns all checksums available in the certificates of the given `parsed_pe`.
 *
 * @param pe the `peparse::parsed_pe` to extract checksums from
 * @return a vector of \ref Checksum
 */
std::vector<Checksum> get_checksums(peparse::parsed_pe *pe);

/**
 * Calculates the requested message digest for the given `parsed_pe`.
 *
 * @param  pe   the `peparse::parsed_pe` to hash
 * @param  kind the kind of message digest to calculate
 * @return      the resulting digest, or an empty string on failure
 */
std::string calculate_checksum(peparse::parsed_pe *pe, checksum_kind kind);

/**
 * Verifies the given `parsed_pe`.
 *
 * A PE is said to be "verified" in the context of uthenticode under the following
 * conditions:
 *
 * 1. It has one or more valid SignedData entries
 * 2. Every SignedData entry has a checksum that matches the PE's calculated checksum
 *
 * @param  pe the `peparse::parsed_pe` to verify
 * @return    true if verified, false otherwise
 */
bool verify(peparse::parsed_pe *pe);

}  // namespace uthenticode
