// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

#include "crypto.h"
#include "crypto_util.h"
#include "buffer.h"
#include <v8.h>
#include <openssl/evp.h>
#include <workerd/jsg/jsg.h>
#include <workerd/api/crypto-impl.h>

namespace workerd::api::node {
jsg::Ref<CryptoImpl::HashHandle> CryptoImpl::HashHandle::constructor(jsg::Lock& js, kj::String algorithm, kj::Maybe<uint32_t> xofLen) {
  return jsg::alloc<CryptoImpl::HashHandle>(algorithm, xofLen);
}

int CryptoImpl::HashHandle::update(jsg::Lock& js, kj::OneOf<v8::Local<v8::String>, kj::Array<kj::byte>> _data, kj::Maybe<kj::String> encoding) {
  KJ_SWITCH_ONEOF(_data) {
    KJ_CASE_ONEOF(string, v8::Local<v8::String>) {
      auto enc = kj::mv(encoding).orDefault(kj::str("utf8"));
      auto data = decodeStringImpl(js, string, getEncoding(enc), true /* strict */);
      JSG_REQUIRE(data.size() <= INT_MAX, RangeError, "data is too long");
      OSSLCALL(EVP_DigestUpdate(md_ctx, data.begin(), data.size()));
    }
    KJ_CASE_ONEOF(data, kj::Array<kj::byte>) {
      JSG_REQUIRE(data.size() <= INT_MAX, RangeError, "data is too long");
      OSSLCALL(EVP_DigestUpdate(md_ctx, data.begin(), data.size()));
    }
  }
  return 1;
}

CryptoImpl::HashHandle::~HashHandle(){
  EVP_MD_CTX_free(md_ctx);
}

kj::OneOf<kj::Array<kj::byte>, v8::Local<v8::String>> CryptoImpl::HashHandle::digest(jsg::Lock& js, kj::Maybe<kj::String> encoding) {
  kj::Vector<kj::byte> data_out;
  unsigned len = md_len;
  data_out.resize(md_len);
  if (EVP_MD_CTX_size(md_ctx) == md_len) {
    OSSLCALL(EVP_DigestFinal_ex(md_ctx, data_out.begin(), &len)); //!= -1//, "failed to produce hash digest");
    KJ_ASSERT(len == md_len);
  } else {
    OSSLCALL(EVP_DigestFinalXOF(md_ctx, data_out.begin(), len));// != -1, "failed to produce XOF hash digest");
  }

  KJ_IF_MAYBE(enc, encoding) {
    auto enc2 = kj::mv(encoding).orDefault(kj::str("utf8"));
    return toStringImpl(js, data_out.releaseAsArray(), 0, md_len, getEncoding(enc2));
  }
  return data_out.releaseAsArray();
}

jsg::Ref<CryptoImpl::HashHandle> CryptoImpl::HashHandle::copy(jsg::Lock& js, kj::Maybe<uint32_t> xofLen) {
  return jsg::alloc<CryptoImpl::HashHandle>(this->md_ctx, xofLen);
}

// TODO: Avoid code duplication
CryptoImpl::HashHandle::HashHandle(EVP_MD_CTX* in_ctx, kj::Maybe<uint32_t> xofLen) {
  const EVP_MD* md = EVP_MD_CTX_md(in_ctx);
  //KJ_ASSERT()?

  md_ctx = EVP_MD_CTX_new();
  // TODO: Error checking
  EVP_DigestInit(md_ctx, md);
  EVP_MD_CTX_copy(md_ctx, in_ctx);

  md_len = EVP_MD_size(md);
  KJ_IF_MAYBE(xof_md_len, xofLen) {
    if (*xof_md_len != md_len) {
      JSG_REQUIRE((EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0, Error, "invalid digest size");
      md_len = *xof_md_len;
    }
  }
};

CryptoImpl::HashHandle::HashHandle(kj::String& algorithm, kj::Maybe<uint32_t> xofLen) {
  const EVP_MD* md = EVP_get_digestbyname(algorithm.begin());
  JSG_REQUIRE(md != nullptr, Error, "Digest method not supported");

  md_ctx = EVP_MD_CTX_new();
  // TODO: Error checking
  EVP_DigestInit(md_ctx, md);

  md_len = EVP_MD_size(md);
  KJ_IF_MAYBE(xof_md_len, xofLen) {
    if (*xof_md_len != md_len) {
      JSG_REQUIRE((EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0, Error, "invalid digest size");
      md_len = *xof_md_len;
    }
  }
};

} // namespace workerd::api::node
