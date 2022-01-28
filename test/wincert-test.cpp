#include <pe-parse/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST_F(Auth32Test, WinCert_properties) {
  auto certs = uthenticode::read_certs(pe);

  ASSERT_TRUE(certs[0].get_length() > 0);
  ASSERT_EQ(certs[0].get_revision(), uthenticode::certificate_revision::CERT_REVISION_2_0);
  ASSERT_EQ(certs[0].get_type(), uthenticode::certificate_type::CERT_TYPE_PKCS_SIGNED_DATA);
}

TEST_F(Auth32DupeTest, WinCert_properties) {
  auto certs = uthenticode::read_certs(pe);

  ASSERT_EQ(certs.size(), 2);
  for (size_t index = 0; index < certs.size(); index++) {
    SCOPED_TRACE("certificate # = " + std::to_string(index));
    ASSERT_TRUE(certs[index].get_length() > 0);
    ASSERT_EQ(certs[index].get_revision(), uthenticode::certificate_revision::CERT_REVISION_2_0);
    ASSERT_EQ(certs[index].get_type(), uthenticode::certificate_type::CERT_TYPE_PKCS_SIGNED_DATA);
  }
}

TEST_F(Auth32PlusTest, WinCert_properties) {
  auto certs = uthenticode::read_certs(pe);

  ASSERT_TRUE(certs[0].get_length() > 0);
  ASSERT_EQ(certs[0].get_revision(), uthenticode::certificate_revision::CERT_REVISION_2_0);
  ASSERT_EQ(certs[0].get_type(), uthenticode::certificate_type::CERT_TYPE_PKCS_SIGNED_DATA);
}
