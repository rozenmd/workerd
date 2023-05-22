// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

#include "crypto.h"
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <workerd/api/crypto-impl.h>
#include <workerd/jsg/jsg.h>

namespace workerd::api::node {

namespace {
// Returns a function that can be used to create an instance of a standardized
// Diffie-Hellman group.
BIGNUM* (*FindDiffieHellmanGroup(const char* name))(BIGNUM*) {
#define V(n, p)                                                                \
  if (strncasecmp(name, n, 7) == 0) {return p;}
  V("modp14", BN_get_rfc3526_prime_2048);
  V("modp15", BN_get_rfc3526_prime_3072);
  V("modp16", BN_get_rfc3526_prime_4096);
  V("modp17", BN_get_rfc3526_prime_6144);
  V("modp18", BN_get_rfc3526_prime_8192);
#undef V
  return nullptr;
}
} // namespace

jsg::Ref<CryptoImpl::DHHandle> CryptoImpl::DHGroupHandle(kj::String name) {
  return jsg::alloc<CryptoImpl::DHHandle>(name);
}

jsg::Ref<CryptoImpl::DHHandle> CryptoImpl::DHHandle::constructor(
    jsg::Lock &js, kj::OneOf<kj::Array<kj::byte>, int> sizeOrKey,
    kj::OneOf<kj::Array<kj::byte>, int> generator) {
  return jsg::alloc<CryptoImpl::DHHandle>(sizeOrKey, generator);
}

bool CryptoImpl::DHHandle::VerifyContext() {
  int codes;
  if (!DH_check(dh, &codes))
    return false;
  verifyError = codes;
  return true;
}

CryptoImpl::DHHandle::DHHandle(kj::OneOf<kj::Array<kj::byte>, int> &sizeOrKey,
                               kj::OneOf<kj::Array<kj::byte>, int> &generator)
                               : dh(nullptr), verifyError(0) {
  JSG_REQUIRE(Init(sizeOrKey, generator), Error, "failed to init DH");
}

CryptoImpl::DHHandle::DHHandle(kj::String& name) : dh(nullptr), verifyError(0) {
  JSG_REQUIRE(InitGroup(name), Error, "failed to init DH");
}

bool CryptoImpl::DHHandle::InitGroup(kj::String& name) {
  auto group = FindDiffieHellmanGroup(name.begin());
  JSG_REQUIRE(group != nullptr, Error, "Failed to init DHGroup: invalid group");
  auto groupKey = group(nullptr);
  KJ_ASSERT(groupKey != nullptr);

  const int kStandardizedGenerator = 2;
  dh = DH_new();

  BIGNUM* bn_g = BN_new();
  if (!BN_set_word(bn_g, kStandardizedGenerator) || !DH_set0_pqg(dh, groupKey, nullptr, bn_g)) {
    BN_free(bn_g);
    JSG_FAIL_REQUIRE(Error, "DHGroup init failed: could not set keys");
  }
  return VerifyContext();
}

bool CryptoImpl::DHHandle::Init(
    kj::OneOf<kj::Array<kj::byte>, int> &sizeOrKey,
    kj::OneOf<kj::Array<kj::byte>, int> &generator) {
  KJ_SWITCH_ONEOF(sizeOrKey) {
    KJ_CASE_ONEOF(size, int) {
      KJ_SWITCH_ONEOF(generator) {
        KJ_CASE_ONEOF(gen, int) {
          dh = DH_new();
          OSSLCALL(DH_generate_parameters_ex(dh, size, gen, nullptr));
          return VerifyContext();
        }
        KJ_CASE_ONEOF(gen, kj::Array<kj::byte>) {
          // Node returns an error in this configuration, not sure why
          JSG_FAIL_REQUIRE(Error, "DH init failed: invalid parameters");
        }
      }
    }
    KJ_CASE_ONEOF(key, kj::Array<kj::byte>) {
      JSG_REQUIRE(key.size() <= INT32_MAX, RangeError, "DH init failed: key is too large");
      JSG_REQUIRE(key.size() > 0, Error, "DH init failed: invalid key");
      dh = DH_new();
      BIGNUM* bn_g;

      KJ_SWITCH_ONEOF(generator) {
        KJ_CASE_ONEOF(gen, int) {
          JSG_REQUIRE(gen >= 2, RangeError, "DH init failed: generator too small");
          bn_g = BN_new();
          if (!BN_set_word(bn_g, gen)) {
            BN_free(bn_g);
            JSG_FAIL_REQUIRE(Error, "DH init failed: could not set keys");
          }
        }
        KJ_CASE_ONEOF(gen, kj::Array<kj::byte>) {
          JSG_REQUIRE(gen.size() <= INT32_MAX, RangeError,
                      "DH init failed: generator is too large");
          JSG_REQUIRE(gen.size() > 0, Error, "DH init failed: invalid generator");

          bn_g = BN_bin2bn(gen.begin(), gen.size(), nullptr);
          if (BN_is_zero(bn_g) || BN_is_one(bn_g)) {
            BN_free(bn_g);
            JSG_FAIL_REQUIRE(Error, "DH init failed: invalid generator");
          }
        }
      }
      BIGNUM* bn_p = BN_bin2bn(key.begin(), key.size(), nullptr);
      if (!bn_p) {
        BN_free(bn_g);
        JSG_FAIL_REQUIRE(Error, "DH init failed: could not convert key representation");
      }
      if (!DH_set0_pqg(dh, bn_p, nullptr, bn_g)) {
        BN_free(bn_p);
        BN_free(bn_g);
        JSG_FAIL_REQUIRE(Error, "DH init failed: could not set keys");
      }
      return VerifyContext();
    }
  }

  KJ_UNREACHABLE;
}

CryptoImpl::DHHandle::~DHHandle() { DH_free(dh); }

void CryptoImpl::DHHandle::setPrivateKey(kj::Array<kj::byte> key) {
  BIGNUM* k = BN_bin2bn(key.begin(), key.size(), nullptr);
  OSSLCALL(DH_set0_key(dh, nullptr, k));
}

void CryptoImpl::DHHandle::setPublicKey(kj::Array<kj::byte> key) {
  BIGNUM* k = BN_bin2bn(key.begin(), key.size(), nullptr);
  OSSLCALL(DH_set0_key(dh, k, nullptr));
}

kj::Array<kj::byte> CryptoImpl::DHHandle::getPublicKey() {
  const BIGNUM *pub_key;
  DH_get0_key(dh, &pub_key, nullptr);

  size_t key_size = BN_num_bytes(pub_key);
  auto key_enc = kj::heapArray<kj::byte>(key_size);
  int next = BN_bn2binpad(pub_key, key_enc.begin(), key_size);
  JSG_REQUIRE(next == (int)key_size, Error, "Error while retrieving DH public key");
  return key_enc;
}

kj::Array<kj::byte> CryptoImpl::DHHandle::getPrivateKey() {
  const BIGNUM *priv_key;
  DH_get0_key(dh, nullptr, &priv_key);

  size_t key_size = BN_num_bytes(priv_key);
  auto key_enc = kj::heapArray<kj::byte>(key_size);
  int next = BN_bn2binpad(priv_key, key_enc.begin(), key_size);
  JSG_REQUIRE(next == (int)key_size, Error, "Error while retrieving DH private key");
  return key_enc;
}

kj::Array<kj::byte> CryptoImpl::DHHandle::getGenerator() {
  const BIGNUM* g;
  DH_get0_pqg(dh, nullptr, nullptr, &g);

  size_t gen_size = BN_num_bytes(g);
  auto gen_enc = kj::heapArray<kj::byte>(gen_size);
  int next = BN_bn2binpad(g, gen_enc.begin(), gen_size);
  JSG_REQUIRE(next == (int)gen_size, Error, "Error while retrieving DH generator");
  return gen_enc;
}

kj::Array<kj::byte> CryptoImpl::DHHandle::getPrime() {
  const BIGNUM* p;
  DH_get0_pqg(dh, &p, nullptr, nullptr);

  size_t prime_size = BN_num_bytes(p);
  auto prime_enc = kj::heapArray<kj::byte>(prime_size);
  int next = BN_bn2binpad(p, prime_enc.begin(), prime_size);
  JSG_REQUIRE(next == (int)prime_size, Error, "Error while retrieving DH prime");
  return prime_enc;
}

namespace {
void ZeroPadDiffieHellmanSecret(size_t remainder_size,
                                unsigned char* data,
                                size_t prime_size) {
  // DH_size returns number of bytes in a prime number.
  // DH_compute_key returns number of bytes in a remainder of exponent, which
  // may have less bytes than a prime number. Therefore add 0-padding to the
  // allocated buffer.
  if (remainder_size != prime_size) {
    KJ_ASSERT(remainder_size < prime_size);
    const size_t padding = prime_size - remainder_size;
    memmove(data + padding, data, remainder_size);
    memset(data, 0, padding);
  }
}
} // namespace

kj::Array<kj::byte> CryptoImpl::DHHandle::computeSecret(kj::Array<kj::byte> key) {
  JSG_REQUIRE(key.size() <= INT32_MAX, RangeError, "DH computeSecret() failed: key is too large");
  JSG_REQUIRE(key.size() > 0, Error, "DH computeSecret() failed: invalid key");

  auto k = OSSLCALL_OWN(BIGNUM, BN_bin2bn(key.begin(), key.size(), nullptr), Error,
                        "Error getting key while computing DH secret");
  size_t prime_size = DH_size(dh);
  auto prime_enc = kj::heapArray<kj::byte>(prime_size);

  int size = DH_compute_key(prime_enc.begin(), k.get(), dh);
  if (size == -1) {
    // various error checking
    int checkResult;
    int checked = DH_check_pub_key(dh, k, &checkResult);

    if (checked && checkResult) {
      JSG_REQUIRE(!(checkResult & DH_CHECK_PUBKEY_TOO_SMALL), RangeError,
                  "DH computeSecret() failed: Supplied key is too small");
      JSG_REQUIRE(!(checkResult & DH_CHECK_PUBKEY_TOO_LARGE), RangeError,
                  "DH computeSecret() failed: Supplied key is too large");
    }
    JSG_FAIL_REQUIRE(Error, "Invalid Key");
  }

  KJ_ASSERT(size >= 0);
  ZeroPadDiffieHellmanSecret(size, prime_enc.begin(), prime_size);
  return prime_enc;
}

kj::Array<kj::byte> CryptoImpl::DHHandle::generateKeys() {
  OSSLCALL(DH_generate_key(dh));
  const BIGNUM* pub_key;
  DH_get0_key(dh, &pub_key, nullptr);

  const int size = BN_num_bytes(pub_key);
  auto prime_enc = kj::heapArray<kj::byte>(size);

  KJ_ASSERT(size > 0);
  JSG_REQUIRE(size == BN_bn2binpad(pub_key, prime_enc.begin(), size), Error,
              "failed to convert DH key representation");

  return prime_enc;
}

int CryptoImpl::DHHandle::getVerifyError() { return verifyError; }

} // namespace workerd::api::node
