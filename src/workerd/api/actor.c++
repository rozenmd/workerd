// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "actor.h"
#include "util.h"
#include <kj/encoding.h>
#include <kj/compat/http.h>
#include <capnp/compat/byte-stream.h>
#include <capnp/compat/http-over-capnp.h>
#include <capnp/schema.h>
#include <capnp/message.h>

namespace workerd::api {

class LocalActorOutgoingFactory final: public Fetcher::OutgoingFactory {
public:
  LocalActorOutgoingFactory(uint channelId, kj::String actorId)
    : channelId(channelId),
      actorId(kj::mv(actorId)) {}

  kj::Own<WorkerInterface> newSingleUseClient(kj::Maybe<kj::String> cfStr) override {
    auto& context = IoContext::current();

    // Lazily initialize actorChannel
    if (actorChannel == nullptr) {
      auto& context = IoContext::current();
      actorChannel = context.getColoLocalActorChannel(channelId, actorId);
    }

    return context.getMetrics().wrapActorSubrequestClient(context.getSubrequest(
        [&](SpanBuilder& span, IoChannelFactory& ioChannelFactory) {
      if (span.isObserved()) {
        span.setTag("actor_id"_kj, kj::str(actorId));
      }

      return KJ_REQUIRE_NONNULL(actorChannel)->startRequest({
        .cfBlobJson = kj::mv(cfStr),
        .parentSpan = span
      });
    }, {
      .inHouse = true,
      .wrapMetrics = true,
      .operationName = "actor_subrequest"_kj
    }));
  }

private:
  uint channelId;
  kj::String actorId;
  kj::Maybe<kj::Own<IoChannelFactory::ActorChannel>> actorChannel;
};

class GlobalActorOutgoingFactory final: public Fetcher::OutgoingFactory {
public:
  GlobalActorOutgoingFactory(
      uint channelId,
      jsg::Ref<DurableObjectId> id,
      kj::Maybe<kj::String> locationHint,
      ActorGetMode mode)
    : channelId(channelId),
      id(kj::mv(id)),
      locationHint(kj::mv(locationHint)),
      mode(mode) {}

  kj::Own<WorkerInterface> newSingleUseClient(kj::Maybe<kj::String> cfStr) override {
    auto& context = IoContext::current();

    // Lazily initialize actorChannel
    if (actorChannel == nullptr) {
      auto& context = IoContext::current();
      actorChannel = context.getGlobalActorChannel(channelId, id->getInner(), kj::mv(locationHint),
          mode);
    }

    return context.getMetrics().wrapActorSubrequestClient(context.getSubrequest(
        [&](SpanBuilder& span, IoChannelFactory& ioChannelFactory) {
      if (span.isObserved()) {
        span.setTag("actor_id"_kj, id->toString());
      }

      return KJ_REQUIRE_NONNULL(actorChannel)->startRequest({
        .cfBlobJson = kj::mv(cfStr),
        .parentSpan = span
      });
    }, {
      .inHouse = true,
      .wrapMetrics = true,
      .operationName = "actor_subrequest"_kj
    }));
  }

private:
  uint channelId;
  jsg::Ref<DurableObjectId> id;
  kj::Maybe<kj::String> locationHint;
  ActorGetMode mode;
  kj::Maybe<kj::Own<IoChannelFactory::ActorChannel>> actorChannel;
};

jsg::Ref<Fetcher> ColoLocalActorNamespace::get(kj::String actorId) {
  JSG_REQUIRE(actorId.size() > 0 && actorId.size() <= 2048, TypeError,
      "Actor ID length must be in the range [1, 2048].");

  auto& context = IoContext::current();

  kj::Own<api::Fetcher::OutgoingFactory> factory = kj::heap<LocalActorOutgoingFactory>(
      channel, kj::mv(actorId));
  auto outgoingFactory = context.addObject(kj::mv(factory));

  bool isInHouse = true;
  return jsg::alloc<Fetcher>(
      kj::mv(outgoingFactory), Fetcher::RequiresHostAndProtocol::YES, isInHouse);
}

// =======================================================================================

kj::String DurableObjectId::toString() {
  return id->toString();
}

jsg::Ref<DurableObjectId> DurableObjectNamespace::newUniqueId(
    jsg::Optional<NewUniqueIdOptions> options) {
  return jsg::alloc<DurableObjectId>(idFactory->newUniqueId(options.orDefault({}).jurisdiction));
}

jsg::Ref<DurableObjectId> DurableObjectNamespace::idFromName(kj::String name) {
  return jsg::alloc<DurableObjectId>(idFactory->idFromName(kj::mv(name)));
}

jsg::Ref<DurableObjectId> DurableObjectNamespace::idFromString(kj::String id) {
  return jsg::alloc<DurableObjectId>(idFactory->idFromString(kj::mv(id)));
}

jsg::Ref<DurableObject> DurableObjectNamespace::get(
    jsg::Ref<DurableObjectId> id,
    jsg::Optional<GetDurableObjectOptions> options,
    CompatibilityFlags::Reader featureFlags) {
  return getImpl(ActorGetMode::GET_OR_CREATE, kj::mv(id), kj::mv(options), kj::mv(featureFlags));
}

jsg::Ref<DurableObject> DurableObjectNamespace::getExisting(
    jsg::Ref<DurableObjectId> id,
    jsg::Optional<GetDurableObjectOptions> options,
    CompatibilityFlags::Reader featureFlags) {
  return getImpl(ActorGetMode::GET_EXISTING, kj::mv(id), kj::mv(options), kj::mv(featureFlags));
}

jsg::Ref<DurableObject> DurableObjectNamespace::getImpl(
    ActorGetMode mode,
    jsg::Ref<DurableObjectId> id,
    jsg::Optional<GetDurableObjectOptions> options,
    CompatibilityFlags::Reader featureFlags) {
  JSG_REQUIRE(idFactory->matchesJurisdiction(id->getInner()), TypeError,
      "get called on jurisdictional subnamespace with an ID from a different jurisdiction");

  auto& context = IoContext::current();
  kj::Maybe<kj::String> locationHint = nullptr;
  KJ_IF_MAYBE(o, options) {
    locationHint = kj::mv(o->locationHint);
  }

  auto outgoingFactory = context.addObject<Fetcher::OutgoingFactory>(
      kj::heap<GlobalActorOutgoingFactory>(channel, id.addRef(), kj::mv(locationHint), mode));
  auto requiresHost = featureFlags.getDurableObjectFetchRequiresSchemeAuthority()
      ? Fetcher::RequiresHostAndProtocol::YES
      : Fetcher::RequiresHostAndProtocol::NO;
  return jsg::alloc<DurableObject>(kj::mv(id), kj::mv(outgoingFactory), requiresHost);
}

jsg::Ref<DurableObjectNamespace> DurableObjectNamespace::jurisdiction(kj::String jurisdiction) {
  return jsg::alloc<api::DurableObjectNamespace>(channel,
      idFactory->cloneWithJurisdiction(jurisdiction));
}

}  // namespace workerd::api
