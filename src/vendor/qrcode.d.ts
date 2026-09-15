//---------------------------------------------------------------------
//
// QR Code Generator for JavaScript - TypeScript Declaration File
//
// Copyright (c) 2016 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//  http://www.opensource.org/licenses/mit-license.php
//
// The word 'QR Code' is registered trademark of
// DENSO WAVE INCORPORATED
//  http://www.denso-wave.com/qrcode/faqpatent-e.html
//
// Vendored from qrcode-generator@1.4.4 (package/qrcode.d.ts, MIT). The
// original declares an ambient module 'qrcode-generator'; this copy is adapted
// for our local import path (./vendor/qrcode.js) by exposing the factory as
// the DEFAULT export. The vendored .js carries a real ESM `export default`
// (added 2026-09-15: the UMD build alone has NO default export under Node ESM
// because the package is "type": "module" — `export default qrcode;` at the
// module level makes Node and Bun agree), so the declaration matches the
// runtime and typechecks without esModuleInterop.
//
//---------------------------------------------------------------------
type TypeNumber =
  | 0 // Automatic type number
  | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10
  | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20
  | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30
  | 31 | 32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 40
  ;

type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';
type Mode = 'Numeric' | 'Alphanumeric' | 'Byte' /* Default */ | 'Kanji';

interface QRCodeFactory {
  (typeNumber: TypeNumber, errorCorrectionLevel: ErrorCorrectionLevel): QRCode;
  stringToBytes(s: string): number[];
  stringToBytesFuncs: { [encoding: string]: (s: string) => number[] };
  createStringToBytes(unicodeData: string, numChars: number): (s: string) => number[];
}

interface QRCode {
  addData(data: string, mode?: Mode): void;
  make(): void;
  getModuleCount(): number;
  isDark(row: number, col: number): boolean;
}

declare const qrcode: QRCodeFactory;
export default qrcode;