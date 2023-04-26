// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
//
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// LazyTransform is a special type of Transform stream that is lazily loaded.
// This is used for performance with bi-API-ship: when two APIs are available
// for the stream, one conventional and one non-conventional.
'use strict';

import {
  getDefaultEncoding,
} from 'node-internal:crypto_util';

import { Transform } from 'node-internal:streams_transform';

export function LazyTransform(this: any, options: any) {
  this._options = options;
}

Object.setPrototypeOf(LazyTransform.prototype, Transform.prototype);
Object.setPrototypeOf(LazyTransform, Transform);

function makeGetter(this: any, name: any) {
  return function(this: any) {
    Transform.call(this, this._options);
    this._writableState.decodeStrings = false;

    if (!this._options || !this._options.defaultEncoding) {
      this._writableState.defaultEncoding = getDefaultEncoding();
    }

    return this[name];
  };
}

function makeSetter(this: any, name: any) {
  return function(this: any, val: any) {
    Object.defineProperty(this, name, {
      // https://github.com/microsoft/TypeScript/issues/13933 ugh
      //__proto__: null,
      value: val,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  };
}

Object.defineProperties(LazyTransform.prototype, {
  _readableState: {
    //__proto__: null,
    get: makeGetter('_readableState'),
    set: makeSetter('_readableState'),
    configurable: true,
    enumerable: true,
  },
  _writableState: {
    //__proto__: null,
    get: makeGetter('_writableState'),
    set: makeSetter('_writableState'),
    configurable: true,
    enumerable: true,
  },
});
