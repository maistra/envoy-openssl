set -x 

SOURCE_DIR=$1
TARGET=$2
PROXY_SHA=$3

if [ "${GIT_RESET}" == "true" ]; then
  pushd ${SOURCE_DIR}
    git fetch upstream
    git checkout master
    git reset --hard 8912fa36acdf4367d37998d98cead376762d2b49 #upstream/master
  popd
fi

if [ "$TARGET" == "RESET" ]; then
  exit
fi

BUILD_OPTIONS="
build --cxxopt -D_GLIBCXX_USE_CXX11_ABI=1
build --cxxopt -DENVOY_IGNORE_GLIBCXX_USE_CXX11_ABI_ERROR=1
build --cxxopt -Wnon-virtual-dtor
build --cxxopt -Wformat
build --cxxopt -Wformat-security
build --cxxopt -Wno-error=deprecated-declarations
build --cxxopt -Wno-error=unused-variable
build --cxxopt -w
build --cxxopt -ldl
"
echo "${BUILD_OPTIONS}" >> ${SOURCE_DIR}/.bazelrc

if [ "$TARGET" == "BORINGSSL" ]; then
  exit
fi

rm -rf ${SOURCE_DIR}/source/extensions/transport_sockets/tls
rm -rf ${SOURCE_DIR}/source/extensions/filters/listener/tls_inspector
rm -rf ${SOURCE_DIR}/test/extensions/transport_sockets/tls
rm -rf ${SOURCE_DIR}/test/extensions/filters/listener/tls_inspector
/usr/bin/cp -rf source/extensions/transport_sockets/tls ${SOURCE_DIR}/source/extensions/transport_sockets/
/usr/bin/cp -rf source/extensions/filters/listener/tls_inspector ${SOURCE_DIR}/source/extensions/filters/listener/
/usr/bin/cp -rf test/extensions/transport_sockets/tls ${SOURCE_DIR}/test/extensions/transport_sockets/
/usr/bin/cp -rf test/extensions/filters/listener/tls_inspector ${SOURCE_DIR}/test/extensions/filters/listener/
/usr/bin/cp -rf test/common/network/* ${SOURCE_DIR}/test/common/network/
/usr/bin/cp -rf test/integration/* ${SOURCE_DIR}/test/integration/

/usr/bin/cp openssl.BUILD ${SOURCE_DIR}

function replace_text() {
  START=$(grep -nr "${DELETE_START_PATTERN}" ${SOURCE_DIR}/${FILE} | cut -d':' -f1)
  START=$((${START} + ${START_OFFSET}))
  if [[ ! -z "${DELETE_STOP_PATTERN}" ]]; then
    STOP=$(tail --lines=+${START}  ${SOURCE_DIR}/${FILE} | grep -nr "${DELETE_STOP_PATTERN}" - |  cut -d':' -f1 | head -1)
    CUT=$((${START} + ${STOP} - 1))
  else
    CUT=$((${START}))
  fi
  CUT_TEXT=$(sed -n "${START},${CUT} p" ${SOURCE_DIR}/${FILE})
  sed -i "${START},${CUT} d" ${SOURCE_DIR}/${FILE}

  if [[ ! -z "${ADD_TEXT}" ]]; then
    ex -s -c "${START}i|${ADD_TEXT}" -c x ${SOURCE_DIR}/${FILE}
  fi
}

FILE="bazel/repository_locations.bzl"
DELETE_START_PATTERN="boringssl = dict("
DELETE_STOP_PATTERN="),"
START_OFFSET="0"
ADD_TEXT="    #EXTERNAL OPENSSL
    bssl_wrapper = dict(
        sha256 = \"5c712e4945f39ce2d3f6420f1dfb82980653f0e85bf50968f7cb2be90d6edbf2\",
        strip_prefix = \"bssl_wrapper-044202abbd4a345f2067e2a51f46ad4468237c59\",
        urls = [\"https://github.com/bdecoste/bssl_wrapper/archive/044202abbd4a345f2067e2a51f46ad4468237c59.tar.gz\"],
    ),
    #EXTERNAL OPENSSL
    openssl_cbs = dict(
        sha256 = \"f466ca7bc4b876cfa9edb4870275207e580588f85f8fae268c40277846a6d8de\",
        strip_prefix = \"openssl-cbs-dab3282af49f134766abcda5f95cbb19057a53d1\",
        urls = [\"https://github.com/maistra/openssl-cbs/archive/dab3282af49f134766abcda5f95cbb19057a53d1.tar.gz\"],
    ),"
replace_text

FILE="bazel/repository_locations.bzl"
DELETE_START_PATTERN="boringssl_fips = dict("
DELETE_STOP_PATTERN="),"
START_OFFSET="0"
ADD_TEXT=""
replace_text

if [ "$UPDATE_JWT" == "true" ]; then
  FILE="bazel/repository_locations.bzl"
  DELETE_START_PATTERN="com_github_google_jwt_verify = dict("
  DELETE_STOP_PATTERN="),"
  START_OFFSET="0"
  ADD_TEXT="    # EXTERNAL OPENSSL
    com_github_google_jwt_verify = dict(
        sha256 = \"bc5a7954a985b23bf5ed31527764572562f3b92476a5f0e296a3c07d0e93f903\",
        strip_prefix = \"jwt_verify_lib-389bfdceef7e79b05315c83b5e7cab37728e2e5b\",
        urls = [\"https://github.com/bdecoste/jwt_verify_lib/archive/389bfdceef7e79b05315c83b5e7cab37728e2e5b.tar.gz\"],
    ),"
  replace_text
fi

FILE="bazel/repositories.bzl"
DELETE_START_PATTERN="def _boringssl():"
DELETE_STOP_PATTERN=" )"
START_OFFSET="0"
ADD_TEXT="#EXTERNAL OPENSSL
def _openssl():
    native.bind(
        name = \"ssl\",
        actual = \"@openssl//:openssl-lib\",
)

#EXTERNAL OPENSSL
def _bssl_wrapper():
    _repository_impl(\"bssl_wrapper\")
    native.bind(
        name = \"bssl_wrapper_lib\",
        actual = \"@bssl_wrapper//:bssl_wrapper_lib\",
    )

#EXTERNAL OPENSSL
def _openssl_cbs():
    _repository_impl(\"openssl_cbs\")
    native.bind(
        name = \"openssl_cbs_lib\",
        actual = \"@openssl_cbs//:openssl_cbs_lib\",
    )"
replace_text

FILE="bazel/repositories.bzl"
DELETE_START_PATTERN="_boringssl()"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="
    # EXTERNAL OPENSSL
    _openssl()
    _bssl_wrapper()
    _openssl_cbs()

"
replace_text

FILE="bazel/repositories.bzl"
DELETE_START_PATTERN="_boringssl_fips()"
DELETE_STOP_PATTERN=")"
START_OFFSET="0"
ADD_TEXT=""
replace_text

FILE="bazel/repositories.bzl"
DELETE_START_PATTERN="@envoy//bazel:boringssl"
DELETE_STOP_PATTERN=")"
START_OFFSET="-2"
ADD_TEXT=""
replace_text

OPENSSL_REPO="
new_local_repository(
    name = \"openssl\",
    path = \"/usr/lib64/\",
    build_file = \"openssl.BUILD\"
)"
echo "${OPENSSL_REPO}" >> ${SOURCE_DIR}/WORKSPACE

sed -i 's|go_register_toolchains(go_version = GO_VERSION)|go_register_toolchains(go_version = "host")|g' ${SOURCE_DIR}/WORKSPACE

FILE="source/extensions/quic_listeners/quiche/platform/BUILD"
DELETE_START_PATTERN="\"ssl\""
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="        \"ssl\",
        \"openssl_cbs_lib\","
replace_text

FILE="bazel/envoy_build_system.bzl"
DELETE_START_PATTERN="def envoy_select_boringssl"
DELETE_STOP_PATTERN="})"
START_OFFSET="0"
ADD_TEXT=""
replace_text

FILE="source/common/common/BUILD"
DELETE_START_PATTERN="\"envoy_select_boringssl\","
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT=""
replace_text

FILE="source/common/common/BUILD"
DELETE_START_PATTERN="copts = envoy_select_boringssl("
DELETE_STOP_PATTERN="),"
START_OFFSET="0"
ADD_TEXT=""
replace_text

FILE="source/common/network/connection_impl.cc"
DELETE_START_PATTERN="close(ConnectionCloseType::NoFlush)"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="  if (ioHandle().fd() == -1 && delayed_close_timer_ == nullptr) {
    close(ConnectionCloseType::NoFlush);
  }"
replace_text

FILE="source/common/network/connection_impl.cc"
DELETE_START_PATTERN="ConnectionImpl file event was unexpectedly reset"
DELETE_STOP_PATTERN="file_event_->activate(Event::FileReadyType::Write)"
START_OFFSET="0"
ADD_TEXT="      ASSERT(file_event_ != nullptr, \"ConnectionImpl file event was unexpectedly reset\");
      if (file_event_ != nullptr) {
        file_event_->activate(Event::FileReadyType::Write);
      }"
replace_text

sed -i "s|ENVOY_SSL_VERSION|\"OpenSSL_1_1_1-${PROXY_SHA}\"|g" ${SOURCE_DIR}/source/common/common/version.cc

sed -i 's|#include "openssl/base.h"|#include "opensslcbs/cbs.h"|g' ${SOURCE_DIR}/source/extensions/quic_listeners/quiche/platform/quic_cert_utils_impl.h
sed -i 's|#include "openssl/bytestring.h"||g' ${SOURCE_DIR}/source/extensions/quic_listeners/quiche/platform/quic_cert_utils_impl.cc
sed -i 's|QuicPlatformTest, QuicStackTraceTest|QuicPlatformTest, DISABLED_QuicStackTraceTest|g' ${SOURCE_DIR}/test/extensions/quic_listeners/quiche/platform/quic_platform_test.cc

sed -i 's|#include "openssl/bytestring.h"||g' ${SOURCE_DIR}/source/common/crypto/utility.cc
sed -i 's|EVP_DigestVerifyInit(ctx.get()|EVP_DigestVerifyInit(ctx|g' ${SOURCE_DIR}/source/common/crypto/utility.cc
sed -i 's|EVP_DigestVerify(ctx.get()|EVP_DigestVerify(ctx|g' ${SOURCE_DIR}/source/common/crypto/utility.cc

FILE="source/common/crypto/utility.cc"
DELETE_START_PATTERN="EVP_parse_public_key"
DELETE_STOP_PATTERN="EVP_parse_public_key"
START_OFFSET="-1"
ADD_TEXT="  const uint8_t* data = reinterpret_cast<const uint8_t*>(key.data());
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &data, key.size());
  return PublicKeyPtr(pkey);"
replace_text

FILE="source/common/crypto/utility.cc"
DELETE_START_PATTERN="ScopedEVP_MD_CTX"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_new();"
replace_text

FILE="source/common/crypto/utility.h"
DELETE_START_PATTERN="openssl/evp.h"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="#include \"openssl/evp.h\"
#include \"opensslcbs/cbs.h\"
#include \"bssl_wrapper/bssl_wrapper.h\""
replace_text

FILE="source/common/crypto/BUILD"
DELETE_START_PATTERN="\"ssl\""
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="        \"ssl\",
        \"openssl_cbs_lib\",
        \"bssl_wrapper_lib\""
replace_text

sed -i 's|#include "openssl/bytestring.h"|#include "opensslcbs/cbs.h"|g' ${SOURCE_DIR}/source/extensions/filters/http/lua/lua_filter.cc
sed -i 's|#include "openssl/base64.h"||g' ${SOURCE_DIR}/source/extensions/filters/http/lua/lua_filter.cc

FILE="source/extensions/filters/http/lua/BUILD"
DELETE_START_PATTERN="lua_filter.h"
DELETE_STOP_PATTERN="deps = ["
START_OFFSET="0"
ADD_TEXT="    hdrs = [\"lua_filter.h\"],
    external_deps = [
      \"openssl_cbs_lib\",
    ],"
replace_text

sed -i 's|#include "openssl/base64.h"||g' ${SOURCE_DIR}/test/extensions/filters/http/lua/lua_filter_test.cc
sed -i 's|#include "openssl/bytestring.h"||g' ${SOURCE_DIR}/test/extensions/filters/http/lua/lua_filter_test.cc
