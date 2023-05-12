// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

#include "crypto.h"
#include "crypto_util.h"
#include <v8.h>
#include <openssl/evp.h>
#include <workerd/jsg/jsg.h>
#include <workerd/api/crypto-impl.h>

namespace workerd::api::node {
jsg::Ref<CryptoImpl::HashHandle> CryptoImpl::HashHandle::constructor(jsg::Lock& js, kj::String algorithm, kj::Maybe<uint32_t> xofLen) {
  return jsg::alloc<CryptoImpl::HashHandle>(algorithm, xofLen);
}

int CryptoImpl::HashHandle::update(jsg::Lock& js, kj::Array<kj::byte> data) {
  JSG_REQUIRE(data.size() <= INT_MAX, RangeError, "data is too long");
  OSSLCALL(EVP_DigestUpdate(md_ctx, data.begin(), data.size()));
  return 1;
}

CryptoImpl::HashHandle::~HashHandle(){
  EVP_MD_CTX_free(md_ctx);
}

kj::Array<kj::byte> CryptoImpl::HashHandle::digest(jsg::Lock& js) {
  kj::Vector<kj::byte> data_out;
  unsigned len = md_len;
  data_out.resize(md_len);
  // TODO: Update error handling to provide useful error messages
  if (EVP_MD_CTX_size(md_ctx) == md_len) {
    OSSLCALL(EVP_DigestFinal_ex(md_ctx, data_out.begin(), &len)); //!= -1//, "failed to produce hash digest");
    KJ_ASSERT(len == md_len);
  } else {
    OSSLCALL(EVP_DigestFinalXOF(md_ctx, data_out.begin(), len));// != -1, "failed to produce XOF hash digest");
  }

  return data_out.releaseAsArray();
}

jsg::Ref<CryptoImpl::HashHandle> CryptoImpl::HashHandle::copy(jsg::Lock& js, kj::Maybe<uint32_t> xofLen) {
  return jsg::alloc<CryptoImpl::HashHandle>(this->md_ctx, xofLen);
}

void CryptoImpl::HashHandle::checkDigestLength(const EVP_MD* md, kj::Maybe<uint32_t> xofLen) {
  md_ctx = EVP_MD_CTX_new();
  JSG_REQUIRE(md_ctx != nullptr, Error, "Failed to allocate hash context");
  EVP_DigestInit(md_ctx, md);
  md_len = EVP_MD_size(md);
  KJ_IF_MAYBE(xof_md_len, xofLen) {
    if (*xof_md_len != md_len) {
      JSG_REQUIRE((EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0, Error, "invalid digest size");
      md_len = *xof_md_len;
    }
  }
}

CryptoImpl::HashHandle::HashHandle(EVP_MD_CTX* in_ctx, kj::Maybe<uint32_t> xofLen) {
  const EVP_MD* md = EVP_MD_CTX_md(in_ctx);
  KJ_ASSERT(md != nullptr);
  checkDigestLength(md, xofLen);
  EVP_MD_CTX_copy(md_ctx, in_ctx);
};

CryptoImpl::HashHandle::HashHandle(kj::String& algorithm, kj::Maybe<uint32_t> xofLen) {
  const EVP_MD* md = EVP_get_digestbyname(algorithm.begin());
  JSG_REQUIRE(md != nullptr, Error, "Digest method not supported");
  checkDigestLength(md, xofLen);
};

} // namespace workerd::api::node
