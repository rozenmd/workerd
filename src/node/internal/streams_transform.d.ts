/* todo: the following is adopted code, enabling linting one day */
/* eslint-disable */

// TODO: Need to add TypeScript bindings for Duplex and underlying types, or find a workaround

/*export class Transform extends Duplex {
    constructor(opts?: TransformOptions);
    _transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}*/
export class Transform  {
    constructor(opts?: any);
    _transform(chunk: any, encoding: any, callback: any): void;
    _flush(callback: any): void;
}