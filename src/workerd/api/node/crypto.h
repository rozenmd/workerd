#pragma once

#include <workerd/jsg/jsg.h>
#include <workerd/api/crypto.h>

namespace workerd::api::node {

class CryptoImpl final: public jsg::Object {
public:
  // DH
  class DHHandle final: public jsg::Object {
    public:
      DHHandle(kj::OneOf<kj::Array<kj::byte>, int>& sizeOrKey, kj::OneOf<kj::Array<kj::byte>, int>& generator);
      DHHandle(kj::String& name);
      ~DHHandle();

      static jsg::Ref<DHHandle> constructor(jsg::Lock& js, kj::OneOf<kj::Array<kj::byte>, int> sizeOrKey, kj::OneOf<kj::Array<kj::byte>, int> generator);

      void setPrivateKey(kj::Array<kj::byte> key);
      void setPublicKey(kj::Array<kj::byte> key);
      kj::Array<kj::byte> getPublicKey();
      kj::Array<kj::byte> getPrivateKey();
      kj::Array<kj::byte> getGenerator();
      kj::Array<kj::byte> getPrime();
      kj::Array<kj::byte> computeSecret(kj::Array<kj::byte> key);
      kj::Array<kj::byte> generateKeys();
      int getVerifyError();

      JSG_RESOURCE_TYPE(DHHandle) {
        JSG_METHOD(setPublicKey);
        JSG_METHOD(setPrivateKey);
        JSG_METHOD(getPublicKey);
        JSG_METHOD(getPrivateKey);
        JSG_METHOD(getGenerator);
        JSG_METHOD(getPrime);
        JSG_METHOD(computeSecret);
        JSG_METHOD(generateKeys);
        JSG_METHOD(getVerifyError);
      };

    private:
      DH* dh;
      int verifyError;

      bool VerifyContext();
      bool Init(kj::OneOf<kj::Array<kj::byte>, int>& sizeOrKey, kj::OneOf<kj::Array<kj::byte>, int>& generator);
      bool InitGroup(kj::String& name);
  };

  jsg::Ref<CryptoImpl::DHHandle> DHGroupHandle(kj::String name);

  // Primes
  kj::Array<kj::byte> randomPrime(uint32_t size, bool safe,
      jsg::Optional<kj::Array<kj::byte>> add, jsg::Optional<kj::Array<kj::byte>> rem);

  bool checkPrimeSync(kj::Array<kj::byte> bufferView, uint32_t num_checks);

  // Pbkdf2
  kj::Array<kj::byte> getPbkdf(kj::Array<kj::byte> password, kj::Array<kj::byte> salt,
                               uint32_t num_iterations, uint32_t keylen, kj::String name);

  // Keys
  struct KeyExportOptions {
    jsg::Optional<kj::String> type;
    jsg::Optional<kj::String> format;
    jsg::Optional<kj::String> cipher;
    jsg::Optional<kj::Array<kj::byte>> passphrase;
    JSG_STRUCT(type, format, cipher, passphrase);
  };

  struct GenerateKeyPairOptions {
    jsg::Optional<uint32_t> modulusLength;
    jsg::Optional<uint64_t> publicExponent;
    jsg::Optional<kj::String> hashAlgorithm;
    jsg::Optional<kj::String> mgf1HashAlgorithm;
    jsg::Optional<uint32_t> saltLength;
    jsg::Optional<uint32_t> divisorLength;
    jsg::Optional<kj::String> namedCurve;
    jsg::Optional<kj::Array<kj::byte>> prime;
    jsg::Optional<uint32_t> primeLength;
    jsg::Optional<uint32_t> generator;
    jsg::Optional<kj::String> groupName;
    jsg::Optional<kj::String> paramEncoding; // one of either 'named' or 'explicit'
    jsg::Optional<KeyExportOptions> publicKeyEncoding;
    jsg::Optional<KeyExportOptions> privateKeyEncoding;

    JSG_STRUCT(modulusLength,
               publicExponent,
               hashAlgorithm,
               mgf1HashAlgorithm,
               saltLength,
               divisorLength,
               namedCurve,
               prime,
               primeLength,
               generator,
               groupName,
               paramEncoding,
               publicKeyEncoding,
               privateKeyEncoding);
  };

  struct CreateAsymmetricKeyOptions {
    kj::OneOf<kj::Array<kj::byte>, SubtleCrypto::JsonWebKey, jsg::Ref<CryptoKey>> key;
    // For a PrivateKey, the key is one of either kj::Array<kj::byte> or
    // SubtleCrypto::JsonWebKey. For a PublicKey it can also be a CryptoKey
    // containing a private key from which the public key will be derived.
    jsg::Optional<kj::String> format;
    jsg::Optional<kj::String> type;
    jsg::Optional<kj::Array<kj::byte>> passphrase;
    // The passphrase is only used for private keys. The format, type, and passphrase
    // options are only used if the key is a kj::Array<kj::byte>.
    JSG_STRUCT(key, format, type, passphrase);
  };

  kj::OneOf<kj::String, kj::Array<kj::byte>, SubtleCrypto::JsonWebKey> exportKey(
      jsg::Lock& js,
      jsg::Ref<CryptoKey> key,
      jsg::Optional<KeyExportOptions> options);

  bool equals(jsg::Lock& js, jsg::Ref<CryptoKey> key, jsg::Ref<CryptoKey> otherKey);

  CryptoKey::AsymmetricKeyDetails getAsymmetricKeyDetail(jsg::Lock& js, jsg::Ref<CryptoKey> key);
  kj::StringPtr getAsymmetricKeyType(jsg::Lock& js, jsg::Ref<CryptoKey> key);

  CryptoKeyPair generateKeyPair(jsg::Lock& js, kj::String type, GenerateKeyPairOptions options);

  jsg::Ref<CryptoKey> createSecretKey(jsg::Lock& js, kj::Array<kj::byte>);
  jsg::Ref<CryptoKey> createPrivateKey(jsg::Lock& js, CreateAsymmetricKeyOptions options);
  jsg::Ref<CryptoKey> createPublicKey(jsg::Lock& js, CreateAsymmetricKeyOptions options);

  JSG_RESOURCE_TYPE(CryptoImpl) {
    // DH
    JSG_NESTED_TYPE(DHHandle);
    JSG_METHOD(DHGroupHandle);
    // Primes
    JSG_METHOD(randomPrime);
    JSG_METHOD(checkPrimeSync);
    // Pbkdf2
    JSG_METHOD(getPbkdf);
    // Keys
    JSG_METHOD(exportKey);
    JSG_METHOD(equals);
    JSG_METHOD(getAsymmetricKeyDetail);
    JSG_METHOD(getAsymmetricKeyType);
    JSG_METHOD(generateKeyPair);
    JSG_METHOD(createSecretKey);
    JSG_METHOD(createPrivateKey);
    JSG_METHOD(createPublicKey);
  }
};

#define EW_NODE_CRYPTO_ISOLATE_TYPES                   \
    api::node::CryptoImpl,                             \
    api::node::CryptoImpl::DHHandle,                   \
    api::node::CryptoImpl::KeyExportOptions,           \
    api::node::CryptoImpl::GenerateKeyPairOptions,     \
    api::node::CryptoImpl::CreateAsymmetricKeyOptions
}  // namespace workerd::api::node
