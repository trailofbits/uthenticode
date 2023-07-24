#include <pe-parse/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST_F(Auth32Test, SignedData_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(signed_data->verify_signature());

  auto checksum = signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA1);
  auto const checksumstr = std::get<std::string>(checksum);
  ASSERT_EQ(checksumstr.size(), 40);
  ASSERT_STRCASEEQ(checksumstr.c_str(), "6663dd7c24fa84fce7f16e0b02689952c06cfa22");

  ASSERT_EQ(signed_data->get_nested_signed_data(), std::nullopt);
}

TEST_F(Auth32DupeTest, SignedData_properties) {
  auto certs = uthenticode::read_certs(pe);
  EXPECT_EQ(certs.size(), 2);

  for (size_t index = 0; index < certs.size(); index++) {
    SCOPED_TRACE("certificate # = " + std::to_string(index));
    auto signed_data = certs[index].as_signed_data();

    ASSERT_TRUE(signed_data.has_value());

    ASSERT_EQ(signed_data->get_signers().size(), 1);
    ASSERT_EQ(signed_data->get_certificates().size(), 1);
    ASSERT_TRUE(signed_data->verify_signature());

    auto checksum = signed_data->get_checksum();
    ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA1);
    auto const checksumstr = std::get<std::string>(checksum);
    ASSERT_EQ(checksumstr.size(), 40);
    ASSERT_STRCASEEQ(checksumstr.c_str(), "6663dd7c24fa84fce7f16e0b02689952c06cfa22");

    ASSERT_EQ(signed_data->get_nested_signed_data(), std::nullopt);
  }
}

TEST_F(Auth32PlusTest, SignedData_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);

  ASSERT_TRUE(signed_data->verify_signature());

  auto checksum = signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA1);
  auto const checksumstr = std::get<std::string>(checksum);
  ASSERT_EQ(checksumstr.size(), 40);
  ASSERT_STRCASEEQ(checksumstr.c_str(), "2559e91a60953a5e16f9650f5f88953a2cca5425");

  ASSERT_EQ(signed_data->get_nested_signed_data(), std::nullopt);
}

TEST_F(AuthNest32Test, SignedData_properties_nested) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());
  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(signed_data->verify_signature());

  auto nested_signed_data = signed_data->get_nested_signed_data();

  ASSERT_TRUE(nested_signed_data.has_value());
  ASSERT_EQ(nested_signed_data->get_signers().size(), 1);
  ASSERT_EQ(nested_signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(nested_signed_data->verify_signature());

  auto checksum = nested_signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA256);
  auto const checksumstr = std::get<std::string>(checksum);
  ASSERT_EQ(checksumstr.size(), 64);
  ASSERT_STRCASEEQ(checksumstr.c_str(),
                   "f10c2600304ec64414a97e10cb19dd4c755f9e7079f85feb38ee7ff9f938db99");
}

TEST_F(AuthNest32PlusTest, SignedData_properties_nested) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());
  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(signed_data->verify_signature());

  auto nested_signed_data = signed_data->get_nested_signed_data();

  ASSERT_TRUE(nested_signed_data.has_value());
  ASSERT_EQ(nested_signed_data->get_signers().size(), 1);
  ASSERT_EQ(nested_signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(nested_signed_data->verify_signature());

  auto checksum = nested_signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA256);
  auto const checksumstr = std::get<std::string>(checksum);
  ASSERT_EQ(checksumstr.size(), 64);
  ASSERT_STRCASEEQ(checksumstr.c_str(),
                   "ddc5b39c4292120745eb86a67eaa331032cc05a0dafaf6e28ec9aa0f189c408d");
}

TEST_F(MissingEKUTest, SignedData_missing_codesigning_EKU) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_FALSE(signed_data->verify_signature());
}
