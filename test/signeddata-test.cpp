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
  ASSERT_EQ(std::get<std::string>(checksum), "6663dd7c24fa84fce7f16eb2689952c06cfa22");

  ASSERT_EQ(signed_data->get_nested_signed_data(), std::nullopt);
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
  ASSERT_EQ(std::get<std::string>(checksum), "2559e91a60953a5e16f965f5f88953a2cca5425");

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
  ASSERT_EQ(std::get<std::string>(checksum),
            "f1c260304ec64414a97e10cb19dd4c755f9e7079f85feb38ee7ff9f938db99");
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
  ASSERT_EQ(std::get<std::string>(checksum),
            "ddc5b39c429212745eb86a67eaa331032cc5a0dafaf6e28ec9aaf189c408d");
}
