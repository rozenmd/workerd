// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#pragma once

#include <kj/debug.h>

#include <workerd/io/worker-interface.capnp.h>
#include <workerd/api/global-scope.h>
#include <workerd/io/worker-interface.h>

namespace workerd::api {

class HibernatableWebSocketEvent final: public ExtendableEvent {
public:
  explicit HibernatableWebSocketEvent();

  static jsg::Ref<HibernatableWebSocketEvent> constructor(kj::String type) = delete;

  jsg::Ref<WebSocket> getWebSocket(jsg::Lock& lock);
  jsg::Value convertError(jsg::Lock& lock, kj::Exception e) {
    return lock.exceptionToJs(kj::mv(e));
  }

  JSG_RESOURCE_TYPE(HibernatableWebSocketEvent) {
    JSG_INHERIT(ExtendableEvent);
  }
};

class HibernatableWebSocketCustomEventImpl final: public WorkerInterface::CustomEvent,
    public kj::Refcounted {
public:
  HibernatableWebSocketCustomEventImpl(
      uint16_t typeId,
      kj::TaskSet& waitUntilTasks,
      HibernatableSocketParams params,
      Worker::Actor::HibernationManager& manager)
    : typeId(typeId), waitUntilTasks(waitUntilTasks), params(kj::mv(params)), manager(manager) {}

  kj::Promise<Result> run(
      kj::Own<IoContext_IncomingRequest> incomingRequest,
      kj::Maybe<kj::StringPtr> entrypointName) override;

  kj::Promise<Result> sendRpc(
      capnp::HttpOverCapnpFactory& httpOverCapnpFactory,
      capnp::ByteStreamFactory& byteStreamFactory,
      kj::TaskSet& waitUntilTasks,
      rpc::EventDispatcher::Client dispatcher) override;

  uint16_t getType() override {
    return typeId;
  }

private:
  uint16_t typeId;
  kj::TaskSet& waitUntilTasks;
  HibernatableSocketParams params;
  Worker::Actor::HibernationManager& manager;
};

#define EW_WEB_SOCKET_MESSAGE_ISOLATE_TYPES      \
  api::HibernatableWebSocketEvent,       \
  api::HibernatableWebSocketExportedHandler
}  // namespace workerd::api
