#include <pe-parse/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST(read_certs, handles_nullptr) {
  auto certs = uthenticode::read_certs(nullptr);

  EXPECT_EQ(certs.size(), 0);
}

TEST_F(NoAuthTest, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 0);
}

TEST_F(Auth32Test, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 1);
  EXPECT_TRUE(certs[0].as_signed_data().has_value());
}

TEST_F(Auth32DupeTest, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 2);
  for (size_t index = 0; index < certs.size(); index++) {
    SCOPED_TRACE("certificate # = " + std::to_string(index));
    EXPECT_TRUE(certs[index].as_signed_data().has_value());
  }
}

TEST_F(Auth32PlusTest, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 1);
  EXPECT_TRUE(certs[0].as_signed_data().has_value());
}

TEST_F(NoAuthTest, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 0);
}

TEST_F(Auth32Test, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 1);
  EXPECT_EQ(std::get<uthenticode::checksum_kind>(checksums[0]), uthenticode::checksum_kind::SHA1);
}

TEST_F(Auth32DupeTest, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 2);
  for (size_t index = 0; index < checksums.size(); index++) {
    SCOPED_TRACE("checksum # = " + std::to_string(index));
    EXPECT_EQ(std::get<uthenticode::checksum_kind>(checksums[index]),
              uthenticode::checksum_kind::SHA1);
  }
}

TEST_F(Auth32PlusTest, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 1);
  EXPECT_EQ(std::get<uthenticode::checksum_kind>(checksums[0]), uthenticode::checksum_kind::SHA1);
}

TEST_F(NoAuthTest, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_FALSE(unk.has_value());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_FALSE(md5.has_value());

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_FALSE(sha1.has_value());

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_FALSE(sha256.has_value());
}

TEST_F(Auth32Test, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_FALSE(unk.has_value());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5.value().size(), 32);
  EXPECT_STRCASEEQ(md5.value().c_str(), "64c29391b57679b2973ac562cf64685d");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1.value().size(), 40);
  EXPECT_STRCASEEQ(sha1.value().c_str(), "6663dd7c24fa84fce7f16e0b02689952c06cfa22");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256.value().size(), 64);
  EXPECT_STRCASEEQ(sha256.value().c_str(),
                   "ea013992f99840f76dcac225dd1262edcec3254511b250a6d1e98d99fc48f815");
}

TEST_F(Auth32DupeTest, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_FALSE(unk.has_value());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5.value().size(), 32);
  EXPECT_STRCASEEQ(md5.value().c_str(), "64c29391b57679b2973ac562cf64685d");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1.value().size(), 40);
  EXPECT_STRCASEEQ(sha1.value().c_str(), "6663dd7c24fa84fce7f16e0b02689952c06cfa22");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256.value().size(), 64);
  EXPECT_STRCASEEQ(sha256.value().c_str(),
                   "ea013992f99840f76dcac225dd1262edcec3254511b250a6d1e98d99fc48f815");
}

TEST_F(Auth32PlusTest, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_FALSE(unk.has_value());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5.value().size(), 32);
  EXPECT_STRCASEEQ(md5.value().c_str(), "ea0235b77d552633c5a38974cef0e2b5");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1.value().size(), 40);
  EXPECT_STRCASEEQ(sha1.value().c_str(), "2559e91a60953a5e16f9650f5f88953a2cca5425");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256.value().size(), 64);
  EXPECT_STRCASEEQ(sha256.value().c_str(),
                   "5c823491c5991914aec971d9456d93d6cf2b8ee7e0ed7abc0b77031d8ec073c0");
}

TEST(verify, handles_nullptr) {
  EXPECT_FALSE(uthenticode::verify(nullptr));
}

TEST_F(NoAuthTest, verify) {
  EXPECT_FALSE(uthenticode::verify(pe));
}

TEST_F(Auth32Test, verify) {
  EXPECT_TRUE(uthenticode::verify(pe));
}

TEST_F(Auth32DupeTest, verify) {
  // File is doctored and therefore signatures (and PE checksum) are invalid, but
  // this isn't checked here. Instead this checks the signature, but not _against_
  // the file hash (minus checksum, minus security data directory).
  EXPECT_TRUE(uthenticode::verify(pe));
}

TEST_F(Auth32PlusTest, verify) {
  EXPECT_TRUE(uthenticode::verify(pe));
}

TEST_F(MissingEKUTest, verify) {
  EXPECT_FALSE(uthenticode::verify(pe));
}

TEST_F(StuffingTest, verify) {
  EXPECT_FALSE(uthenticode::verify(pe));
}
