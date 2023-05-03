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

/* todo: the following is adopted code, enabling linting one day */
/* eslint-disable */

'use strict';

import { default as cryptoImpl } from 'node-internal:crypto';

import {
    kHandle,
} from 'node-internal:crypto_util';

import {
    Buffer
} from 'node-internal:internal_buffer';

import {
    ERR_CRYPTO_HASH_FINALIZED,
    ERR_CRYPTO_HASH_UPDATE_FAILED,
    ERR_INVALID_ARG_TYPE,
} from 'node-internal:internal_errors';

import {
    validateEncoding,
    validateString,
    validateUint32,
} from 'node-internal:validators';

import {
    normalizeEncoding
} from 'node-internal:internal_utils';

import {
    isArrayBufferView
} from 'node-internal:internal_types';

import {
  LazyTransform
} from 'node-internal:lazy_transform';

const kState = Symbol('kState');
const kFinalized = Symbol('kFinalized');

// TODO: How to turn Hash into an actual type so we don't have to use any?
export function Hash(this: any, algorithm: string, options: any = {}) : any {
  validateString(algorithm, 'algorithm');
  const xofLen = typeof options === 'object' && options !== null ?
    options.outputLength : undefined;
  if (xofLen !== undefined)
    validateUint32(xofLen, 'options.outputLength');
  this[kHandle] = new cryptoImpl.HashHandle(algorithm, xofLen as number);
  this[kState] = {
    [kFinalized]: false,
  };
  typeof Reflect.apply(LazyTransform, this, [options]);
}

typeof Object.setPrototypeOf(Hash.prototype, LazyTransform.prototype);
typeof Object.setPrototypeOf(Hash, LazyTransform);

// TODO: Ugly workaround
Hash.prototype.copy = function copy(options: any): any {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  const xofLen = typeof options === 'object' && options !== null ?
  options.outputLength : undefined;
if (xofLen !== undefined)
  validateUint32(xofLen, 'options.outputLength');

  const h = new (Hash as any)('md5');
  h[kHandle] = this[kHandle].copy(xofLen as number);
  return h;
};

Hash.prototype._transform = function _transform(chunk: Buffer | string | any, encoding: string, callback: Function) {
  this[kHandle].update(chunk, encoding);
  callback();
};

Hash.prototype._flush = function _flush(callback: Function) {
  this.push(this[kHandle].digest());
  callback();
};

Hash.prototype.update = function update(data: string | Buffer | DataView, encoding?: string) {
  encoding = encoding || 'utf8';
  if (encoding != undefined && encoding === 'buffer') {
    encoding = undefined;
  }

  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  if (typeof data === 'string') {
    validateEncoding(data, encoding!); encoding = normalizeEncoding(encoding!);
  } else if (!isArrayBufferView(data)) {
    throw new ERR_INVALID_ARG_TYPE(
      'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
  }

  if (!this[kHandle].update(data, encoding))
    throw new ERR_CRYPTO_HASH_UPDATE_FAILED();
  return this;
};

Hash.prototype.digest = function digest(outputEncoding?: string): Buffer | string {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();
  if (outputEncoding != undefined && outputEncoding === 'buffer') {
    outputEncoding = undefined;
  }

  // Explicit conversion for backward compatibility.
  const ret = this[kHandle].digest(outputEncoding);
  state[kFinalized] = true;
  return ret;
};
