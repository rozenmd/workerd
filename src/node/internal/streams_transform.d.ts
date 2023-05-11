/* todo: the following is adopted code, enabling linting one day */
/* eslint-disable */

// TODO: Need to add TypeScript bindings for Stream.Transform and underlying types, or find a workaround
export class TransformDummy {
    constructor(opts?: any);
    _transform(chunk: any, encoding: any, callback: any): void;
    _flush(callback: any): void;

    // Actually in class further down, more complex
    push(chunk: any): any;
}

export interface TransformOptionsDummy {

}