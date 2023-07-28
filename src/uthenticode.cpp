#include "uthenticode.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <utility>

namespace uthenticode {
namespace impl {
// clang-format off
ASN1_SEQUENCE(Authenticode_SpcAttributeTypeAndOptionalValue) = {
  ASN1_SIMPLE(Authenticode_SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
  ASN1_OPT(Authenticode_SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(Authenticode_SpcAttributeTypeAndOptionalValue)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(Authenticode_DigestInfo) = {
  ASN1_SIMPLE(Authenticode_DigestInfo, digestAlgorithm, X509_ALGOR),
  ASN1_SIMPLE(Authenticode_DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Authenticode_DigestInfo)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_DigestInfo)

ASN1_SEQUENCE(Authenticode_SpcIndirectDataContent) = {
  ASN1_SIMPLE(Authenticode_SpcIndirectDataContent, data, Authenticode_SpcAttributeTypeAndOptionalValue),
  ASN1_SIMPLE(Authenticode_SpcIndirectDataContent, messageDigest, Authenticode_DigestInfo)
} ASN1_SEQUENCE_END(Authenticode_SpcIndirectDataContent)
IMPLEMENT_ASN1_FUNCTIONS(Authenticode_SpcIndirectDataContent)

/* OpenSSL defines OPENSSL_free as a macro, which we can't use with decltype.
 * So we wrap it here for use with unique_ptr.
 */
void OpenSSL_free(void *ptr) {
  OPENSSL_free(ptr);
}

void SK_X509_free(stack_st_X509 *ptr) {
  sk_X509_free(ptr);
}

// clang-format on
}  // namespace impl

/**
 * Rounds `x` up to the nearest multiple of `factor`.
 *
 * @param  x      the number to round
 * @param  factor the factor to round by
 * @return        the rounded number
 */
static inline std::size_t round(std::size_t x, std::size_t factor) {
  auto rem = x % factor;
  if (rem == 0) {
    return x;
  }
  return x + factor - rem;
}

/**
 * Converts the given buffer into a hexadecimal string representation.
 *
 * @param  buf the input buffer
 * @param  len the buffer's size
 * @return     the hex string
 */
static inline std::string tohex(std::uint8_t *buf, std::size_t len) {
  constexpr static char lookup_table[] = "0123456789ABCDEF";

  if (!buf || !len) {
    return {};
  }

  std::string hexstr;
  hexstr.reserve(len * 2);  // each byte creates two hex digits

  for (auto i = 0; i < len; i++) {
    hexstr += lookup_table[buf[i] >> 4];
    hexstr += lookup_table[buf[i] & 0xF];
  }

  return hexstr;
}

/**
 * Convert the given checksum_kind to an OpenSSL NID.
 *
 * @param  kind the checksum_kind to convert
 * @return      an integer representing the corresponding OpenSSL NID
 */
static inline int checksum_type_to_nid(checksum_kind kind) {
  switch (kind) {
    default:
      return NID_undef;
    case checksum_kind::MD5:
      return NID_md5;
    case checksum_kind::SHA1:
      return NID_sha1;
    case checksum_kind::SHA256:
      return NID_sha256;
  }
}

/**
 * Convert the given OpenSSL NID to a checksum_kind.
 *
 * @param  nid the NID to convert
 * @return     the corresponding checksum_kind
 */
static inline checksum_kind nid_to_checksum_kind(int nid) {
  switch (nid) {
    default:
      return checksum_kind::UNKNOWN;
    case NID_md5:
      return checksum_kind::MD5;
    case NID_sha1:
      return checksum_kind::SHA1;
    case NID_sha256:
      return checksum_kind::SHA256;
  }
}

std::ostream &operator<<(std::ostream &os, checksum_kind kind) {
  switch (kind) {
    default:
      return os << static_cast<std::uint16_t>(kind);
    case checksum_kind::MD5:
      return os << "MD5";
    case checksum_kind::SHA1:
      return os << "SHA1";
    case checksum_kind::SHA256:
      return os << "SHA256";
  }
}

Certificate::Certificate(X509 *cert) {
  auto subject = impl::OpenSSL_ptr(X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0),
                                   impl::OpenSSL_free);
  auto issuer = impl::OpenSSL_ptr(X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0),
                                  impl::OpenSSL_free);
  auto serial_bn = impl::BN_ptr(ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), nullptr), BN_free);
  auto serial_number = impl::OpenSSL_ptr(BN_bn2hex(serial_bn.get()), impl::OpenSSL_free);

  subject_ = std::string(subject.get());
  issuer_ = std::string(issuer.get());
  serial_number_ = std::string(serial_number.get());
}

SignedData::SignedData(std::vector<std::uint8_t> cert_buf) : cert_buf_(cert_buf) {
  auto *buf_ptr = BIO_new_mem_buf(cert_buf_.data(), static_cast<int>(cert_buf_.size()));
  if (buf_ptr == nullptr) {
    throw std::bad_alloc{};
  }
  impl::BIO_ptr buf(buf_ptr, BIO_free);

  p7_ = d2i_PKCS7_bio(buf.get(), nullptr);
  if (p7_ == nullptr) {
    throw FormatError{"Couldn't parse PKCS#7 SignedData"};
  }

  /* NOTE(ww): This call is safe within the constructor, since get_indirect_data
   * only requires p7_ to be initialized (which happens immediately above).
   */
  indirect_data_ = get_indirect_data();
  if (indirect_data_ == nullptr) {
    throw FormatError{"Couldn't parse SpcIndirectDataContent"};
  }
}

SignedData::SignedData(SignedData &&s) noexcept
    : cert_buf_(std::move(s.cert_buf_)),
      p7_(std::exchange(s.p7_, nullptr)),
      indirect_data_(std::exchange(s.indirect_data_, nullptr)) {
}

SignedData::~SignedData() {
  if (p7_ != nullptr) {
    PKCS7_free(p7_);
  }

  if (indirect_data_ != nullptr) {
    impl::Authenticode_SpcIndirectDataContent_free(indirect_data_);
  }
}

bool SignedData::verify_signature() const {
  STACK_OF(X509) *certs = nullptr;
  switch (OBJ_obj2nid(p7_->type)) {
    case NID_pkcs7_signed: {
      certs = p7_->d.sign->cert;
      break;
    }
    /* NOTE(ww): I'm pretty sure Authenticode signatures are always SignedData and never
     * SignedAndEnvelopedData, but it doesn't hurt us to handle the latter as well.
     */
    case NID_pkcs7_signedAndEnveloped: {
      certs = p7_->d.signed_and_enveloped->cert;
      break;
    }
  }

  if (certs == nullptr) {
    return false;
  }

  auto *signers_stack_ptr = PKCS7_get0_signers(p7_, nullptr, 0);
  if (signers_stack_ptr == nullptr) {
    return false;
  }
  auto signers_stack = impl::STACK_OF_X509_ptr(signers_stack_ptr, impl::SK_X509_free);

  /* NOTE(ww): Authenticode specification, page 13: the signer must have the
   * codeSigning EKU, **or** no member of the signer's chain may have it.
   *
   * The check below is more strict than that: **every** signer must have
   * the codeSigning EKU, and we don't check the embedded chain (since
   * we can't do full chain verification anyways).
   */
  for (auto i = 0; i < sk_X509_num(signers_stack.get()); ++i) {
    auto *signer = sk_X509_value(signers_stack.get(), i);

    /* NOTE(ww): Ths should really be X509_check_purpose with
     * X509_PURPOSE_CODE_SIGN, but this is inexplicably not present
     * in even the latest releases of OpenSSL as of 2023-05.
     */
    auto xku_flags = X509_get_extended_key_usage(signer);
    if (!(xku_flags & XKU_CODE_SIGN)) {
      return false;
    }
  }

  /* NOTE(ww): What happens below is a bit dumb: we convert our SpcIndirectDataContent back
   * into DER form so that we can unwrap its ASN.1 sequence and pass the underlying data
   * to PKCS7_verify for verification. This displays our intent a little more clearly than
   * our previous approach, which was to walk the PKCS#7 structure manually.
   */
  std::uint8_t *indirect_data_buf = nullptr;
  auto buf_size = impl::i2d_Authenticode_SpcIndirectDataContent(indirect_data_, &indirect_data_buf);
  if (buf_size < 0 || indirect_data_buf == nullptr) {
    return false;
  }
  auto indirect_data_ptr =
      impl::OpenSSL_ptr(reinterpret_cast<char *>(indirect_data_buf), impl::OpenSSL_free);

  const auto *signed_data_seq = reinterpret_cast<std::uint8_t *>(indirect_data_ptr.get());
  long length = 0;
  int tag = 0, tag_class = 0;
  ASN1_get_object(&signed_data_seq, &length, &tag, &tag_class, buf_size);
  if (tag != V_ASN1_SEQUENCE) {
    return false;
  }

  auto *signed_data_ptr = BIO_new_mem_buf(signed_data_seq, length);
  if (signed_data_ptr == nullptr) {
    return false;
  }
  impl::BIO_ptr signed_data(signed_data_ptr, BIO_free);

  /* Our actual verification happens here.
   *
   * We pass `certs` explicitly, but (experimentally) we don't have to -- the function correctly
   * extracts then from the SignedData in `p7_`.
   *
   * We pass `nullptr` for the X509_STORE, since we don't do full-chain verification
   * (we can't, since we don't have access to Windows's Trusted Publishers store on non-Windows).
   */
  auto status = PKCS7_verify(p7_, certs, nullptr, signed_data.get(), nullptr, PKCS7_NOVERIFY);

  return status == 1;
}

Checksum SignedData::get_checksum() const {
  auto nid = OBJ_obj2nid(indirect_data_->messageDigest->digestAlgorithm->algorithm);
  auto digest = tohex(indirect_data_->messageDigest->digest->data,
                      indirect_data_->messageDigest->digest->length);
  return std::make_tuple(nid_to_checksum_kind(nid), digest);
}

std::vector<Certificate> SignedData::get_signers() const {
  auto *signers_stack_ptr = PKCS7_get0_signers(p7_, nullptr, 0);
  if (signers_stack_ptr == nullptr) {
    return {};
  }
  auto signers_stack = impl::STACK_OF_X509_ptr(signers_stack_ptr, impl::SK_X509_free);

  std::vector<Certificate> signers;
  for (auto i = 0; i < sk_X509_num(signers_stack.get()); ++i) {
    /* Frustrating: ideally we'd use emplace_back here, but apparently
     * it gets exploded into some std::allocator scope that makes the private Certificate
     * constructor flip out (since it's only friends with SignedData).
     *
     * Instead, push_back and hope for copy elision (or the default move constructor, maybe).
     */
    signers.push_back(Certificate(sk_X509_value(signers_stack.get(), i)));
  }

  return signers;
}

std::vector<Certificate> SignedData::get_certificates() const {
  auto *certs_stack_ptr = p7_->d.sign->cert;
  if (certs_stack_ptr == nullptr) {
    return {};
  }

  std::vector<Certificate> certs;
  for (auto i = 0; i < sk_X509_num(certs_stack_ptr); ++i) {
    /* Like above: ideally we'd use emplace_back, but C++ gets in the way.
     */
    certs.push_back(Certificate(sk_X509_value(certs_stack_ptr, i)));
  }

  return certs;
}

std::optional<SignedData> SignedData::get_nested_signed_data() const {
  PKCS7_SIGNER_INFO *signer_info = sk_PKCS7_SIGNER_INFO_value(p7_->d.sign->signer_info, 0);

  /* NOTE(ww): OpenSSL stupidity: you actually need to call OBJ_create before
   * OBJ_txt2obj; the latter won't do it for you. Luckily (?) OpenSSL 1.1.0+
   * auto-frees these, so they're not totally impossible to use in leakless C++.
   */
  OBJ_create(impl::SPC_NESTED_SIGNATURE_OID, NULL, NULL);
  auto *spc_nested_sig_oid_ptr = OBJ_txt2obj(impl::SPC_NESTED_SIGNATURE_OID, 1);
  if (spc_nested_sig_oid_ptr == nullptr) {
    return std::nullopt;
  }
  impl::ASN1_OBJECT_ptr spc_nested_sig_oid(spc_nested_sig_oid_ptr, ASN1_OBJECT_free);

  auto *nested_signed_data =
      PKCS7_get_attribute(signer_info, OBJ_obj2nid(spc_nested_sig_oid.get()));
  if (nested_signed_data == nullptr) {
    return std::nullopt;
  }

  if (ASN1_TYPE_get(nested_signed_data) != V_ASN1_SEQUENCE) {
    return std::nullopt;
  }

  auto *nested_signed_data_seq = nested_signed_data->value.sequence;
  std::vector<std::uint8_t> cert_buf(nested_signed_data_seq->data,
                                     nested_signed_data_seq->data + nested_signed_data_seq->length);

  return std::make_optional<SignedData>(cert_buf);
}

impl::Authenticode_SpcIndirectDataContent *SignedData::get_indirect_data() const {
  auto *contents = p7_->d.sign->contents;
  if (contents == nullptr) {
    return nullptr;
  }

  /* We're expecting a sequence whose type is SPC_INDIRECT_DATA_OID.
   */
  OBJ_create(impl::SPC_INDIRECT_DATA_OID, NULL, NULL);
  auto *spc_indir_oid_ptr = OBJ_txt2obj(impl::SPC_INDIRECT_DATA_OID, 1);
  if (spc_indir_oid_ptr == nullptr) {
    return nullptr;
  }
  impl::ASN1_OBJECT_ptr spc_indir_oid(spc_indir_oid_ptr, ASN1_OBJECT_free);

  if (ASN1_TYPE_get(contents->d.other) != V_ASN1_SEQUENCE ||
      OBJ_cmp(contents->type, spc_indir_oid.get())) {
    return nullptr;
  }

  /* TODO: Could probably use a BIO here instead of the direct-from-buffer API.
   */
  const auto *indir_data_inc_ptr = contents->d.other->value.sequence->data;
  auto *indir_data = impl::d2i_Authenticode_SpcIndirectDataContent(
      nullptr, &indir_data_inc_ptr, contents->d.other->value.sequence->length);
  if (indir_data == nullptr) {
    return nullptr;
  }

  /* Sanity checks against SpcIndirectDataContent. It's not clear to me
   * whether a non-nullptr above guarantees any of these fields, so check
   * them manually.
   */
  if (indir_data->messageDigest->digest->data == nullptr ||
      indir_data->messageDigest->digest->length >= contents->d.other->value.sequence->length) {
    return nullptr;
  }

  return indir_data;
}

std::optional<SignedData> WinCert::as_signed_data() const {
  if (type_ != certificate_type::CERT_TYPE_PKCS_SIGNED_DATA) {
    return std::nullopt;
  }

  try {
    return std::make_optional<SignedData>(cert_buf_);
  } catch (FormatError) {
    return std::nullopt;
  }
}

std::vector<WinCert> read_certs(peparse::parsed_pe *pe) {
  if (pe == nullptr) {
    return {};
  }

  std::vector<std::uint8_t> raw_cert_table;
  if (!peparse::GetDataDirectoryEntry(pe, peparse::DIR_SECURITY, raw_cert_table)) {
    return {};
  }

  /* The certificate table is composed of 8-byte aligned entries, each of which looks like this:
   *
   * dwLength (uint32_t): length of the raw certificate data
   * wRevision (uint16_t): the certificate revision number
   * wCertificateType (uint16_t): the kind of data in this certificate entry
   * bCertificate (uint8_t[dwLength - 8]): the raw certificate data in this entry
   */
  std::vector<WinCert> certs;
  auto *current_wincert = raw_cert_table.data();
  auto const *const past_secdir = raw_cert_table.data() + raw_cert_table.size();
  // Let us tread carefully, we expect all members of WIN_CERTIFICATE up to bCertificate
  while (current_wincert + 8 < past_secdir) {
    size_t offset = 0;
    std::uint32_t length = *reinterpret_cast<std::uint32_t *>(current_wincert + offset);
    offset += sizeof(length);

    std::uint16_t revision = *reinterpret_cast<std::uint16_t *>(current_wincert + offset);
    offset += sizeof(revision);

    std::uint16_t type = *reinterpret_cast<std::uint16_t *>(current_wincert + offset);
    offset += sizeof(type);

    // Continue only we can satisfy the length
    if (current_wincert + length <= past_secdir && length > offset) {
      std::vector<std::uint8_t> cert_data(current_wincert + offset, current_wincert + length);

      certs.emplace_back(static_cast<certificate_revision>(revision),
                         static_cast<certificate_type>(type),
                         cert_data);
    }

    current_wincert += std::max<std::size_t>(round(length, 8), 8);
  }

  return certs;
}

std::vector<Checksum> get_checksums(peparse::parsed_pe *pe) {
  std::vector<Checksum> checksums;
  const auto &certs = read_certs(pe);
  if (certs.empty()) {
    return checksums;
  }

  for (const auto &cert : certs) {
    auto signed_data = cert.as_signed_data();
    if (!signed_data) {
      continue;
    }

    checksums.push_back(signed_data->get_checksum());
  }

  return checksums;
}

std::string calculate_checksum(peparse::parsed_pe *pe, checksum_kind kind) {
  auto nid = checksum_type_to_nid(kind);
  if (nid == NID_undef) {
    return {};
  }

  /* In both PEs and PE32+s, the PE checksum is 64 bytes into the optional header,
   * which itself is 24 bytes after the PE magic and COFF header from the offset
   * specified in the DOS header.
   */
  auto pe_checksum_offset = pe->peHeader.dos.e_lfanew + 24 + 64;

  /* The certificate table directory entry offset is also in the optional header,
   * albeit at different offsets for PE32 and PE32+. See each of the cases below.
   */
  std::size_t cert_table_offset = pe->peHeader.dos.e_lfanew + 24;
  std::uint32_t size_of_headers = 0;
  peparse::data_directory security_dir;
  if (pe->peHeader.nt.OptionalMagic == peparse::NT_OPTIONAL_32_MAGIC) {
    security_dir = pe->peHeader.nt.OptionalHeader.DataDirectory[peparse::DIR_SECURITY];
    size_of_headers = pe->peHeader.nt.OptionalHeader.SizeOfHeaders;
    cert_table_offset += 128;
  } else if (pe->peHeader.nt.OptionalMagic == peparse::NT_OPTIONAL_64_MAGIC) {
    security_dir = pe->peHeader.nt.OptionalHeader64.DataDirectory[peparse::DIR_SECURITY];
    size_of_headers = pe->peHeader.nt.OptionalHeader64.SizeOfHeaders;
    cert_table_offset += 144;
  } else {
    /* Mystical future PE version?
     */
    return {};
  }

  /* "VirtualAddress" here is really an offset; an invalid one indicates a tampered input.
   * Similarly, a cert_table_offset beyond size_of_headers indicates a tampered input
   * (we get the pe_checksum_offset check for free, since it's always smaller).
   */
  if (security_dir.VirtualAddress + security_dir.Size > pe->fileBuffer->bufLen ||
      cert_table_offset + 8 > size_of_headers) {
    return {};
  }

  /* Copy everything up to the end of the headers into pe_bits.
   * Use a bounded_buffer to handle the range checks for us.
   */
  auto *header_buf = peparse::splitBuffer(pe->fileBuffer, 0, size_of_headers);
  if (header_buf == nullptr) {
    return {};
  }

  /* We'll stash the bits of the PE that we need to hash in this buffer.
   */
  std::vector<std::uint8_t> pe_bits;
  pe_bits.reserve(size_of_headers);

  pe_bits.insert(pe_bits.begin(), header_buf->buf, header_buf->buf + header_buf->bufLen);
  delete header_buf;

  /* This won't happen under normal conditions, but could with a tampered input.
   * We don't have to check pe_checksum_offset here since it'll always be strictly less
   * than cert_table_offset.
   */
  if (pe_bits.size() <= cert_table_offset + 8) {
    return {};
  }

  /* Erase the PE checksum and certificate table entry from pe_bits.
   * Do the certificate table entry first, so that we don't have to rescale the checksum's offset.
   */
  pe_bits.erase(pe_bits.begin() + cert_table_offset, pe_bits.begin() + cert_table_offset + 8);
  pe_bits.erase(pe_bits.begin() + pe_checksum_offset, pe_bits.begin() + pe_checksum_offset + 4);

  /* Hash pe_bits, which contains the rest of the header.
   */
  const auto *md = EVP_get_digestbynid(nid);
  auto *md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit(md_ctx, md);
  EVP_DigestUpdate(md_ctx, pe_bits.data(), pe_bits.size());

  if (security_dir.VirtualAddress > 0) {
    /* If a certificate table exists, hash everything before and after it.
     */
    EVP_DigestUpdate(md_ctx,
                     pe->fileBuffer->buf + size_of_headers,
                     security_dir.VirtualAddress - size_of_headers);

    /* Most PEs won't have any trailing data but the Authenticode specification is explicit about
     * hashing any if it exists.
     */
    EVP_DigestUpdate(md_ctx,
                     pe->fileBuffer->buf + security_dir.VirtualAddress + security_dir.Size,
                     pe->fileBuffer->bufLen - (security_dir.VirtualAddress + security_dir.Size));
  } else {
    /* If there's no certificate table, just hash the rest of the file.
     */
    EVP_DigestUpdate(
        md_ctx, pe->fileBuffer->buf + size_of_headers, pe->fileBuffer->bufLen - size_of_headers);
  }

  /* Finally, finish hashing the damn thing.
   */
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> md_buf;
  EVP_DigestFinal(md_ctx, md_buf.data(), nullptr);
  EVP_MD_CTX_free(md_ctx);

  return tohex(md_buf.data(), EVP_MD_size(md));
}

bool verify(peparse::parsed_pe *pe) {
  /* Our verification state.
   * A PE is said to be verified if all three are true.
   *
   * We start verified_signed_data and verified_checksum in the true state
   * so that we can AND them against each SignedData's results.
   */
  bool has_signed_data = false, verified_signed_data = true, verified_checksum = true;

  auto certs = read_certs(pe);
  for (const auto &cert : certs) {
    const auto signed_data = cert.as_signed_data();
    if (!signed_data) {
      continue;
    }

    auto embedded_checksum = signed_data->get_checksum();

    has_signed_data = true;
    verified_signed_data = verified_signed_data && signed_data->verify_signature();
    verified_checksum =
        verified_checksum && std::get<std::string>(embedded_checksum) ==
                                 calculate_checksum(pe, std::get<checksum_kind>(embedded_checksum));

    const auto nested_signed_data = signed_data->get_nested_signed_data();
    if (!nested_signed_data) {
      continue;
    }

    auto nested_embedded_checksum = nested_signed_data->get_checksum();

    verified_signed_data = verified_signed_data && nested_signed_data->verify_signature();
    verified_checksum =
        verified_checksum &&
        std::get<std::string>(nested_embedded_checksum) ==
            calculate_checksum(pe, std::get<checksum_kind>(nested_embedded_checksum));
  }

  return has_signed_data && verified_signed_data && verified_checksum;
}

}  // namespace uthenticode
