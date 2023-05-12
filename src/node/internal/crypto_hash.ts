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

import { default as cryptoImpl } from 'node-internal:crypto';

import {
  kHandle,
  kFinalized,
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

// TODO: Need to inherit from stream.Transform, using dummy class is currently disabled to make
// test cases pass
import {
  // TransformDummy,
  TransformOptionsDummy,
} from 'node-internal:streams_transform';

export interface HashOptions extends TransformOptionsDummy {
  outputLength?: number;
}

export function createHash(algorithm: string, options?: HashOptions): Hash {
  validateString(algorithm, 'algorithm');
  const xofLen = typeof options === 'object' && options !== null ?
    options.outputLength : undefined;
  if (xofLen !== undefined)
    validateUint32(xofLen, 'options.outputLength');
  const hHandle = new cryptoImpl.HashHandle(algorithm, xofLen as number);
  return Hash.from(hHandle);
}

// export class Hash extends TransformDummy {
export class Hash {
  private [kHandle]: cryptoImpl.HashHandle;
  private [kFinalized]: boolean;

  constructor() {
    // KeyObjects cannot be created with new ... use one of the
    // create or generate methods, or use from to get from a
    // CryptoKey.
    // TODO
    // super();
    throw new Error('Illegal constructor');
  }

  // TODO: How would I make this externally invisible?
  static from(h: cryptoImpl.HashHandle): Hash {
    return Reflect.construct(function(this: Hash) {
      this[kHandle] = h;
      this[kFinalized] = false;
    }, [], Hash);
  }

  public copy(options?: HashOptions): Hash {
    if (this[kFinalized])
      throw new ERR_CRYPTO_HASH_FINALIZED();

    const xofLen = typeof options === 'object' && options !== null ?
    options.outputLength : undefined;
    if (xofLen !== undefined)
      validateUint32(xofLen, 'options.outputLength');

    const handleCopy = this[kHandle].copy(xofLen as number);
    return Hash.from(handleCopy);
  }

  // override
  _flush(this: Hash, callback: Function): void {
    this[kHandle].digest();
    // this.push(this[kHandle].digest());
    callback();
  }

  // override
  _transform(chunk: Buffer | string | any, encoding: string, callback: Function): void {
    if (typeof chunk === 'string') {
      encoding = encoding || 'utf-8';
      validateEncoding(chunk, encoding); encoding = normalizeEncoding(encoding)!;
      chunk = Buffer.from(chunk, encoding);
    }
    this[kHandle].update(chunk);
    callback();
  }

  public update(data: string | Buffer | ArrayBufferView, encoding?: string): Hash {
    encoding = encoding || 'utf8';
    if (encoding != undefined && encoding === 'buffer') {
      encoding = undefined;
    }

    if (this[kFinalized])
      throw new ERR_CRYPTO_HASH_FINALIZED();

    if (typeof data === 'string') {
      validateEncoding(data, encoding!); encoding = normalizeEncoding(encoding);
      data = Buffer.from(data, encoding);
    } else if (!isArrayBufferView(data)) {
      throw new ERR_INVALID_ARG_TYPE(
        'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
    }

    if (!this[kHandle].update(data))
      throw new ERR_CRYPTO_HASH_UPDATE_FAILED();
    return this;
  }

  public digest(): Buffer;
  public digest(outputEncoding: string): string;
  public digest(outputEncoding?: string): Buffer | string {
    if (this[kFinalized])
      throw new ERR_CRYPTO_HASH_FINALIZED();

    // Explicit conversion for backward compatibility.
    const ret = this[kHandle].digest();
    this[kFinalized] = true;
    if (outputEncoding != undefined && outputEncoding != 'buffer') {
      return Buffer.from(ret).toString(outputEncoding);
    } else {
      return Buffer.from(ret);
    }
  }

}
