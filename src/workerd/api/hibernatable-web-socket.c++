// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "hibernatable-web-socket.h"
#include <workerd/jsg/ser.h>
#include <workerd/io/hibernation-manager.h>

namespace workerd::api {

HibernatableWebSocketEvent::HibernatableWebSocketEvent()
    : ExtendableEvent("webSocketMessage") {};

jsg::Ref<WebSocket> HibernatableWebSocketEvent::getWebSocket(jsg::Lock& lock) {
  auto& manager = static_cast<HibernationManagerImpl&>(
      KJ_REQUIRE_NONNULL(
          KJ_REQUIRE_NONNULL(IoContext::current().getActor()).getHibernationManager()));
  auto& hibernatableWebSocket = KJ_REQUIRE_NONNULL(manager.webSocketForEventHandler);
  if (hibernatableWebSocket.activeWebSocket == nullptr) {
    hibernatableWebSocket.unhibernate(lock);
  }
  return KJ_REQUIRE_NONNULL(hibernatableWebSocket.activeWebSocket).addRef();
}

kj::Promise<WorkerInterface::CustomEvent::Result> HibernatableWebSocketCustomEventImpl::run(
    kj::Own<IoContext_IncomingRequest> incomingRequest,
    kj::Maybe<kj::StringPtr> entrypointName) {
  // Mark the request as delivered because we're about to run some JS.
  auto& context = incomingRequest->getContext();
  incomingRequest->delivered();
  EventOutcome outcome = EventOutcome::OK;

  // We definitely have an actor by this point. Let's set the hibernation manager on the actor
  // before we start running any events that might need to access it.
  auto& a = KJ_REQUIRE_NONNULL(context.getActor());
  if (a.getHibernationManager() == nullptr) {
    a.setHibernationManager(kj::addRef(manager));
  }

  try {
    co_await context.run(
        [entrypointName=entrypointName, &context, params=kj::mv(params)]
        (Worker::Lock& lock) mutable {
      KJ_SWITCH_ONEOF(params.eventType) {
        KJ_CASE_ONEOF(text, HibernatableSocketParams::Text) {
          return lock.getGlobalScope().sendHibernatableWebSocketMessage(
              kj::mv(text.message),
              lock,
              lock.getExportedHandler(entrypointName, context.getActor()));
        }
        KJ_CASE_ONEOF(data, HibernatableSocketParams::Data) {
          return lock.getGlobalScope().sendHibernatableWebSocketMessage(
              kj::mv(data.message),
              lock,
              lock.getExportedHandler(entrypointName, context.getActor()));
        }
        KJ_CASE_ONEOF(close, HibernatableSocketParams::Close) {
          return lock.getGlobalScope().sendHibernatableWebSocketClose(
              kj::mv(close),
              lock,
              lock.getExportedHandler(entrypointName, context.getActor()));
        }
        KJ_CASE_ONEOF(e, HibernatableSocketParams::Error) {
          return lock.getGlobalScope().sendHibernatableWebSocketError(
              kj::mv(e.error),
              lock,
              lock.getExportedHandler(entrypointName, context.getActor()));
        }
        KJ_UNREACHABLE;
      }
    });
  } catch(kj::Exception e) {
    if (auto desc = e.getDescription();
        !jsg::isTunneledException(desc) && !jsg::isDoNotLogException(desc)) {
      LOG_EXCEPTION("HibernatableWebSocketCustomEventImpl"_kj, e);
    }
    outcome = EventOutcome::EXCEPTION;
  }

  waitUntilTasks.add(incomingRequest->drain());

  co_return Result {
    .outcome = outcome,
  };
}

kj::Promise<WorkerInterface::CustomEvent::Result>
  HibernatableWebSocketCustomEventImpl::sendRpc(
    capnp::HttpOverCapnpFactory& httpOverCapnpFactory,
    capnp::ByteStreamFactory& byteStreamFactory,
    kj::TaskSet& waitUntilTasks,
    rpc::EventDispatcher::Client dispatcher) {
  auto req = dispatcher.hibernatableWebSocketMessageRequest();
  // TODO(now): set correct params to rpc using the params set in HibernatableSocketParams

  waitUntilTasks.add(req.send().ignoreResult());

  // If we care about the event result we need to change this
  co_return Result {
    .outcome = workerd::EventOutcome::OK,
  };
}

}  // namespace workerd::api
