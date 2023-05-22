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

import {
  Buffer,
} from 'node-internal:internal_buffer';

import { default as cryptoImpl } from 'node-internal:crypto';
type ArrayLike = cryptoImpl.ArrayLike;

import {
  ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY,
  ERR_INVALID_ARG_TYPE,
} from 'node-internal:internal_errors';

import {
  validateInt32,
} from 'node-internal:validators';

import {
  isArrayBufferView,
  isAnyArrayBuffer
} from 'node-internal:internal_types';

import {
  getArrayBufferOrView,
  toBuf,
  kHandle,
} from 'node-internal:crypto_util';

const DH_GENERATOR = 2;

export class DiffieHellman {
  private [kHandle]: cryptoImpl.DHHandle;

  constructor(sizeOrKey: number|ArrayLike, keyEncoding?: number|string,
              generator?: number|ArrayLike, genEncoding?: string) {
    if (typeof sizeOrKey !== 'number' &&
        typeof sizeOrKey !== 'string' &&
        !isArrayBufferView(sizeOrKey) &&
        !isAnyArrayBuffer(sizeOrKey)) {
      throw new ERR_INVALID_ARG_TYPE(
        'sizeOrKey',
        ['number', 'string', 'ArrayBuffer', 'Buffer', 'TypedArray', 'DataView'],
        sizeOrKey,
      );
    }

    // Sizes < 0 don't make sense but they _are_ accepted (and subsequently
    // rejected with ERR_OSSL_BN_BITS_TOO_SMALL) by OpenSSL. The glue code
    // in node_crypto.cc accepts values that are IsInt32() for that reason
    // and that's why we do that here too.
    if (typeof sizeOrKey === 'number')
      validateInt32(sizeOrKey, 'sizeOrKey');

    if (keyEncoding && !Buffer.isEncoding(keyEncoding) &&
        keyEncoding !== 'buffer') {
      genEncoding = generator as any;
      generator = keyEncoding;
      keyEncoding = "utf-8"; // default encoding
    }

    keyEncoding = keyEncoding || 'utf-8';
    genEncoding = genEncoding || 'utf-8';

    if (typeof sizeOrKey !== 'number')
      sizeOrKey = toBuf(sizeOrKey, keyEncoding as string);

    if (!generator) {
      generator = DH_GENERATOR;
    } else if (typeof generator === 'number') {
      validateInt32(generator, 'generator');
    } else if (typeof generator === 'string') {
      generator = toBuf(generator, genEncoding);
    } else if (!isArrayBufferView(generator) && !isAnyArrayBuffer(generator)) {
      throw new ERR_INVALID_ARG_TYPE(
        'generator',
        ['number', 'string', 'ArrayBuffer', 'Buffer', 'TypedArray', 'DataView'],
        generator,
      );
    }

    this[kHandle] = new cryptoImpl.DHHandle(sizeOrKey as any, generator as any);
  }

  public computeSecret = dhComputeSecret;
  public generateKeys = dhGenerateKeys;
  public getPrime = dhGetPrime;
  public getGenerator = dhGetGenerator;
  public getPrivateKey = dhGetPrivateKey;
  public getPublicKey = dhGetPublicKey;

  public setPublicKey(this: DiffieHellman, key: ArrayLike, encoding?: string): DiffieHellman {
    key = getArrayBufferOrView(key, 'key', encoding);
    this[kHandle].setPublicKey(key);
    return this;
  }

  public setPrivateKey(this: DiffieHellman, key: ArrayLike, encoding?: string): DiffieHellman {
    key = getArrayBufferOrView(key, 'key', encoding);
    this[kHandle].setPrivateKey(key);
    return this;
  }

  public get verifyError(): number { return this[kHandle].getVerifyError(); }
}

export class DiffieHellmanGroup {
  private [kHandle]: cryptoImpl.DHHandle;

  constructor(name: string) {
    this[kHandle] = cryptoImpl.DHGroupHandle(name);
  }

  public computeSecret = dhComputeSecret;
  public generateKeys = dhGenerateKeys;
  public getPrime = dhGetPrime;
  public getGenerator = dhGetGenerator;
  public getPrivateKey = dhGetPrivateKey;
  public getPublicKey = dhGetPublicKey;
  public get verifyError(): number { return this[kHandle].getVerifyError(); }
}

function dhGenerateKeys(this: any, encoding?: string): Buffer|string {
  const keys = this[kHandle].generateKeys();
  return encode(keys, encoding);
}

function dhComputeSecret(this: any, key: ArrayLike, inEnc?: string,
                         outEnc?: string): Buffer|string {
  key = getArrayBufferOrView(key, 'key', inEnc);
  const ret = this[kHandle].computeSecret(key);
  if (typeof ret === 'string')
    throw new ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY();
  return encode(ret, outEnc);
}

function dhGetPrime(this: any, encoding?: string): Buffer|string {
  const prime = this[kHandle].getPrime();
  return encode(prime, encoding);
}

function dhGetGenerator(this: any, encoding?: string): Buffer|string {
  const generator = this[kHandle].getGenerator();
  return encode(generator, encoding);
}

function dhGetPublicKey(this: any, encoding?: string): Buffer|string {
  const key = this[kHandle].getPublicKey();
  return encode(key, encoding);
}

function dhGetPrivateKey(this: any, encoding?: string): Buffer|string {
  const key = this[kHandle].getPrivateKey();
  return encode(key, encoding);
}

function encode(buffer: ArrayBuffer, encoding?: string): Buffer|string {
  if (encoding && encoding !== 'buffer')
    return Buffer.from(buffer).toString(encoding);
  return Buffer.from(buffer);
}

export function createDiffieHellman(sizeOrKey: number|ArrayLike,
                                    keyEncoding?: number|string, generator?: number|ArrayLike,
                                    genEncoding?: string): DiffieHellman {
  return new DiffieHellman(sizeOrKey, keyEncoding, generator, genEncoding);
}

export function createDiffieHellmanGroup(name: string): DiffieHellmanGroup {
  return new DiffieHellmanGroup(name);
}

export function getDiffieHellman(name: string): DiffieHellmanGroup {
  return createDiffieHellmanGroup(name);
}