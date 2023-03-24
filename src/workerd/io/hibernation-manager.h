// Copyright (c) 2017-2023 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#pragma once

#include <kj/debug.h>
#include <workerd/api/web-socket.h>
#include <workerd/api/hibernatable-web-socket.h>
#include "v8-isolate.h"
#include <workerd/jsg/ser.h>

#include <list>

namespace workerd {

class HibernationManagerImpl final : public Worker::Actor::HibernationManager {
  // Implements the HibernationManager class.
public:
  HibernationManagerImpl(kj::Own<Worker::Actor::Loopback> loopback, uint16_t hibernationEventType)
      : loopback(kj::mv(loopback)),
        hibernationEventType(hibernationEventType),
        onDisconnect(DisconnectHandler{}),
        readLoopTasks(onDisconnect) {}
  ~HibernationManagerImpl();

  void acceptWebSocket(jsg::Ref<api::WebSocket> ws, kj::ArrayPtr<kj::String> tags) override;
  // Tells the HibernationManager to create a new HibernatableWebSocket with the associated tags
  // and to initiate the `readLoop()` for this websocket. The `tags` array *must* contain only
  // unique elements.

  kj::Vector<jsg::Ref<api::WebSocket>> getWebSockets(
      jsg::Lock& js,
      kj::Maybe<kj::StringPtr> tag) override;
  // Gets a collection of websockets associated with the given tag. Any hibernating websockets will
  // be woken up. If no tag is provided, we return all accepted websockets.

  void hibernateWebSockets(Worker::Lock& lock) override;
  // Hibernates all the websockets held by the HibernationManager.
  // This converts our activeOrPackage from an api::WebSocket to a HibernationPackage.

  friend jsg::Ref<api::WebSocket> api::HibernatableWebSocketEvent::getWebSocket(jsg::Lock& lock);

  void setEventTimeout(kj::Maybe<int> timeoutMs) override;
  // Sets the maximum time in Ms that an event can run for. If the timeout is reached, event is canceled.

  kj::Maybe<int> getEventTimeout() override;
  // Gets the event timeout.

  void setTimerChannel(TimerChannel& timer) override;
  // Adds a reference to a timechannel to be used for autoresponse timestamp and event timeouts.

private:
  class HibernatableWebSocket;
  struct TagListItem {
    // Each HibernatableWebSocket can have multiple tags, so we want to store a reference
    // in our kj::List.
    kj::Maybe<HibernatableWebSocket&> hibWS;
    kj::ListLink<TagListItem> link;
    kj::StringPtr tag;
    kj::Maybe<kj::List<TagListItem, &TagListItem::link>&> list;
    // The List that refers to this TagListItem.
    // If `list` is null, we've already removed this item from the list.
  };

  class HibernatableWebSocket {
    // api::WebSockets cannot survive hibernation, but kj::WebSockets do. This class helps us
    // manage the transition of an api::WebSocket from its active state to a hibernated state
    // and vice versa.
    //
    // Some properties of the JS websocket object need to be retained throughout hibernation,
    // such as `attachment`, `url`, `extensions`, etc. These properties are only read/modified
    // when initiating, or waking from hibernation.
  public:
    HibernatableWebSocket(jsg::Ref<api::WebSocket> websocket,
                          kj::ArrayPtr<kj::String> tags,
                          HibernationManagerImpl& manager)
        : tagItems(kj::heapArray<TagListItem>(tags.size())),
          activeOrPackage(kj::mv(websocket)),
          // Extract's the kj::Own<kj::WebSocket> from api::WebSocket so the HibernatableWebSocket
          // can own it. The api::WebSocket retains a reference to our ws.
          ws(activeOrPackage.get<jsg::Ref<api::WebSocket>>()->acceptAsHibernatable()),
          manager(manager) {}

    ~HibernatableWebSocket() {
      // We expect this dtor to be called when we're removing a HibernatableWebSocket
      // from our `allWs` collection in the HibernationManager.

      // This removal is fast because we have direct access to each kj::List, as well as direct
      // access to each TagListItem we want to remove.
      for (auto& item: tagItems) {
        KJ_IF_MAYBE(list, item.list) {
          // The list reference is non-null, so we still have a valid reference to this
          // TagListItem in the list, which we will now remove.
          list->remove(item);
          if (list->empty()) {
            // Remove the bucket in tagToWs if the tag has no more websockets.
            manager.tagToWs.erase(kj::mv(item.tag));
          }
        }
        item.hibWS = nullptr;
        item.list = nullptr;
      }
    }

    jsg::Ref<api::WebSocket> getActiveOrUnhibernate(jsg::Lock& js) {
      // Returns a reference to the active websocket. If the websocket is currently hibernating,
      // we have to unhibernate it first. The process moves values from the HibernatableWebSocket
      // to the api::WebSocket.
      KJ_IF_MAYBE(package, activeOrPackage.tryGet<api::WebSocket::HibernationPackage>()) {
        activeOrPackage.init<jsg::Ref<api::WebSocket>>(
            api::WebSocket::hibernatableFromNative(js, *ws, kj::mv(*package)));
      }
      return activeOrPackage.get<jsg::Ref<api::WebSocket>>().addRef();
    }

    kj::ListLink<HibernatableWebSocket> link;

    kj::Array<TagListItem> tagItems;
    // An array of all the items/nodes that refer to this HibernatableWebSocket.
    // Keeping track of these items allows us to quickly remove every reference from `tagToWs`
    // once the websocket disconnects -- rather than iterating through each relevant tag in the
    // hashmap and removing it from each kj::List.

    kj::OneOf<jsg::Ref<api::WebSocket>, api::WebSocket::HibernationPackage> activeOrPackage;
    // If active, we have an api::WebSocket reference, otherwise, we're hibernating, so we retain
    // the websocket's properties in a HibernationPackage until it's time to wake up.
    kj::Own<kj::WebSocket> ws;
    HibernationManagerImpl& manager;
    // TODO(someday): We (currently) only use the HibernationManagerImpl reference to refer to
    // `tagToWs` when running the dtor for `HibernatableWebSocket`. This feels a bit excessive,
    // I would rather have the HibernationManager deal with its collections than have the
    // HibernatableWebSocket do so. Maybe come back to this at some point?
    kj::Maybe<std::list<kj::Own<HibernatableWebSocket>>::iterator> node;
    // Reference to the Node in `allWs` that allows us to do fast deletion on disconnect.

    bool hasDispatchedClose = false;
    // True once we have dispatched the close event.
    // This prevents us from dispatching it if we have already done so.
    friend HibernationManagerImpl;
  };

private:
  void dropHibernatableWebSocket(HibernatableWebSocket& hib);
  // Removes a HibernatableWebSocket from the HibernationManager's various collections.

  inline void removeFromAllWs(HibernatableWebSocket& hib);
  // Removes the HibernatableWebSocket from `allWs`.

  kj::Promise<void> handleSocketTermination(
      HibernatableWebSocket& hib, kj::Maybe<kj::Exception>& maybeError);
  // Handles the termination of the websocket. If termination was not clean, we might try to
  // dispatch a close event (if we haven't already), or an error event.
  // We will also remove the HibernatableWebSocket from the HibernationManager's collections.

  kj::Promise<void> readLoop(HibernatableWebSocket& hib);
  // Like the api::WebSocket readLoop(), but we dispatch different types of events.

  struct TagCollection {
    // This struct is held by the `tagToWs` hashmap. The key is a StringPtr to tag, and the value
    // is this struct itself.
    kj::String tag;
    kj::Own<kj::List<TagListItem, &TagListItem::link>> list;

    TagCollection(kj::String tag, decltype(list) list): tag(kj::mv(tag)), list(kj::mv(list)) {}
    TagCollection(TagCollection&& other) = default;
  };

  kj::HashMap<kj::StringPtr, kj::Own<TagCollection>> tagToWs;
  // A hashmap of tags to HibernatableWebSockets associated with the tag.
  // We use a kj::List so we can quickly remove websockets that have disconnected.
  // Also note that we box the keys and values such that in the event of a hashmap resizing we don't
  // move the underlying data (thereby keeping any references intact).

  std::list<kj::Own<HibernatableWebSocket>> allWs;
  // We store all of our HibernatableWebSockets in a doubly linked-list.

  kj::Own<Worker::Actor::Loopback> loopback;
  // Used to obtain the worker so we can dispatch Hibernatable websocket events.

  uint16_t hibernationEventType;
  // Passed to HibernatableWebSocket custom event as the typeId.

  kj::Maybe<HibernatableWebSocket&> webSocketForEventHandler;
  // Allows the HibernatableWebSocket event handler that is currently running to access the
  // HibernatableWebSocket that it needs to execute.

  const size_t ACTIVE_CONNECTION_LIMIT = 1024 * 32;
  // The maximum number of Hibernatable WebSocket connections a single HibernationManagerImpl
  // instance can manage.

  class DisconnectHandler: public kj::TaskSet::ErrorHandler {
  public:
    void taskFailed(kj::Exception&& exception) override {};
    // We don't need to do anything here; we already handle disconnects in the callee of readLoop().
  };
  DisconnectHandler onDisconnect;
  kj::TaskSet readLoopTasks;
  kj::Maybe<TimerChannel&> timerChannel;
  kj::Maybe<int> eventTimeoutMs;
  // Used to set the event dispatch timeout
};
}; // namespace workerd
