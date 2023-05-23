#include "v8-platform-wrapper.h"
#include <v8-isolate.h>
#include "jsg.h"

namespace workerd::jsg {

V8PlatformWrapper::TaskWrapper::TaskWrapper(std::unique_ptr<v8::Task> inner)
    : inner(kj::mv(inner)), cageCtx(v8::PointerCageContext::GetCurrent()) {}

void V8PlatformWrapper::TaskWrapper::Run() {
  V8StackScope stackScope;
  v8::PointerCageContext::Scope cageScope(cageCtx);
  inner->Run();
}

V8PlatformWrapper::JobTaskWrapper::JobTaskWrapper(std::unique_ptr<v8::JobTask> inner)
    : inner(kj::mv(inner)), cageCtx(v8::PointerCageContext::GetCurrent()) {}

void V8PlatformWrapper::JobTaskWrapper::Run(v8::JobDelegate* delegate) {
  V8StackScope stackScope;
  v8::PointerCageContext::Scope cageScope(cageCtx);
  inner->Run(delegate);
}

}  // namespace workerd::jsg
