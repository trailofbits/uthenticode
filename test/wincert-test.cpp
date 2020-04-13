#include <cstdlib>

#include "gtest/gtest.h"

#include <parser-library/parse.h>
#include <smolverify.h>

#include "helpers.h"

TEST_F(Auth32Test, WinCert_properties) {
  auto certs = smolverify::read_certs(pe);

  ASSERT_TRUE(certs[0].get_length() > 0);
  ASSERT_EQ(certs[0].get_revision(), smolverify::certificate_revision::CERT_REVISION_2_0);
  ASSERT_EQ(certs[0].get_type(), smolverify::certificate_type::CERT_TYPE_PKCS_SIGNED_DATA);
}

TEST_F(Auth32PlusTest, WinCert_properties) {
  auto certs = smolverify::read_certs(pe);

  ASSERT_TRUE(certs[0].get_length() > 0);
  ASSERT_EQ(certs[0].get_revision(), smolverify::certificate_revision::CERT_REVISION_2_0);
  ASSERT_EQ(certs[0].get_type(), smolverify::certificate_type::CERT_TYPE_PKCS_SIGNED_DATA);
}
