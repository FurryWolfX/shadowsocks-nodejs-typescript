import { Cipher, Decipher, Hash } from "crypto";
import * as crypto from "crypto";
import mergeSort from "./mergeSort";

const int32Max: number = Math.pow(2, 32);
const cachedTables: Object = {}; // password: [encryptTable, decryptTable]
const bytesToKeyResults: Object = {};

export function getTable(key: string): Array<Array<number>> {
  if (cachedTables[key]) {
    return cachedTables[key];
  }
  console.log("calculating ciphers");
  let table: Array<number> = new Array(256);
  const decryptTable: Array<number> = new Array(256);
  const md5sum: Hash = crypto.createHash("md5");
  md5sum.update(key);
  const hash: Buffer = md5sum.digest(); // TODO  new Buffer(md5sum.digest(), "binary")
  const al = hash.readUInt32LE(0);
  const ah = hash.readUInt32LE(4);

  let i: number = 0;
  while (i < 256) {
    table[i] = i;
    i++;
  }
  i = 1;
  while (i < 1024) {
    table = mergeSort(
      table,
      (x, y) => (((ah % (x + i)) * int32Max + al) % (x + i)) - (((ah % (y + i)) * int32Max + al) % (y + i)),
    );
    i++;
  }
  i = 0;
  while (i < 256) {
    decryptTable[table[i]] = i;
    ++i;
  }
  const result = [table, decryptTable];
  cachedTables[key] = result;
  return result;
}

function substitute(table: Array<number>, buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    buf[i] = table[buf[i]];
  }
  return buf;
}

function EVP_BytesToKey(password: Buffer, key_len: number, iv_len: number): Array<Buffer> {
  if (bytesToKeyResults[`${password}:${key_len}:${iv_len}`]) {
    return bytesToKeyResults[`${password}:${key_len}:${iv_len}`];
  }
  let m = [];
  let i = 0;
  let count = 0;
  while (count < key_len + iv_len) {
    const md5 = crypto.createHash("md5");
    let data = password;
    if (i > 0) {
      data = Buffer.concat([m[i - 1], password]);
    }
    md5.update(data);
    const d = md5.digest();
    m.push(d);
    count += d.length;
    i++;
  }
  const ms = Buffer.concat(m);
  const key = ms.slice(0, key_len);
  const iv = ms.slice(key_len, key_len + iv_len);
  bytesToKeyResults[password.toString()] = [key, iv];
  return [key, iv];
}

const method_supported = {
  "aes-128-cfb": [16, 16],
  "aes-192-cfb": [24, 16],
  "aes-256-cfb": [32, 16],
  "bf-cfb": [16, 8],
  "camellia-128-cfb": [16, 16],
  "camellia-192-cfb": [24, 16],
  "camellia-256-cfb": [32, 16],
  "cast5-cfb": [16, 8],
  "des-cfb": [8, 8],
  "idea-cfb": [16, 8],
  "rc2-cfb": [16, 8],
  rc4: [16, 0],
  "rc4-md5": [16, 16],
  "seed-cfb": [16, 16],
};

function createRc4Md5Cipher(key, iv, op): Cipher | Decipher {
  const md5: Hash = crypto.createHash("md5");
  md5.update(key);
  md5.update(iv);
  const rc4_key: Buffer = md5.digest();
  if (op == 1) {
    return crypto.createCipheriv("rc4", rc4_key, "");
  } else {
    return crypto.createDecipheriv("rc4", rc4_key, "");
  }
}

export class Encryptor {
  ivSent: boolean;
  cipher: Cipher | Decipher;
  decipher: Cipher | Decipher;
  encryptTable: Array<number>;
  decryptTable: Array<number>;
  cipherIv: Buffer;
  key: string;
  method: string;

  constructor(key, method) {
    this.ivSent = false;
    this.key = key;
    this.method = method;
    if (this.method === "table") {
      this.method = null;
    }
    if (this.method) {
      this.cipher = this.getCipher(this.key, this.method, 1, crypto.randomBytes(32));
    } else {
      [this.encryptTable, this.decryptTable] = getTable(this.key);
    }
  }

  getCipherLen(method) {
    method = method.toLowerCase();
    return method_supported[method];
  }

  getCipher(password: string, method: string, op: number, iv: Buffer): Cipher | Decipher {
    method = method.toLowerCase();
    const passwordBuffer = new Buffer(password, "binary");
    const m = this.getCipherLen(method);
    if (m) {
      let key: Buffer;
      let iv_: Buffer;
      [key, iv_] = EVP_BytesToKey(passwordBuffer, m[0], m[1]);
      if (!iv) {
        iv = iv_;
      }
      if (op === 1) {
        this.cipherIv = iv.slice(0, m[1]);
      }
      iv = iv.slice(0, m[1]);
      if (method === "rc4-md5") {
        return createRc4Md5Cipher(key, iv, op);
      } else {
        if (op === 1) {
          return crypto.createCipheriv(method, key, iv);
        } else {
          return crypto.createDecipheriv(method, key, iv);
        }
      }
    }
  }

  encrypt(buf: Buffer): Buffer {
    if (this.method) {
      const result: Buffer = this.cipher.update(buf);
      if (this.ivSent) {
        return result;
      } else {
        this.ivSent = true;
        return Buffer.concat([this.cipherIv, result]);
      }
    } else {
      return substitute(this.encryptTable, buf);
    }
  }

  decrypt(buf: Buffer): Buffer {
    let decipherIv: Buffer, decipherIvLen: number, result: Buffer;
    if (this.method != null) {
      if (this.decipher == null) {
        decipherIvLen = this.getCipherLen(this.method)[1];
        decipherIv = buf.slice(0, decipherIvLen);
        this.decipher = this.getCipher(this.key, this.method, 0, decipherIv);
        result = this.decipher.update(buf.slice(decipherIvLen));
        return result;
      } else {
        result = this.decipher.update(buf);
        return result;
      }
    } else {
      return substitute(this.decryptTable, buf);
    }
  }
}

export function encryptAll(password: string, method: string, op: number, data: Buffer): Buffer {
  let cipher: Cipher | Decipher, iv, key, result;
  if (method === "table") {
    method = null;
  }
  if (method == null) {
    const tables: Array<Array<any>> = getTable(password);
    const encryptTable: Array<any> = tables[0];
    const decryptTable: Array<any> = tables[1];
    if (op === 0) {
      return substitute(decryptTable, data);
    } else {
      return substitute(encryptTable, data);
    }
  } else {
    result = [];
    method = method.toLowerCase();
    const methodLength: Array<number> = method_supported[method];
    const keyLen: number = methodLength[0];
    const ivLen: number = methodLength[1];
    key = EVP_BytesToKey(new Buffer(password.toString(), "binary"), keyLen, ivLen)[0];
    if (op === 1) {
      iv = crypto.randomBytes(ivLen);
      result.push(iv);
    } else {
      iv = data.slice(0, ivLen);
      data = data.slice(ivLen);
    }
    if (method === "rc4-md5") {
      cipher = createRc4Md5Cipher(key, iv, op);
    } else {
      if (op === 1) {
        cipher = crypto.createCipheriv(method, key, iv);
      } else {
        cipher = crypto.createDecipheriv(method, key, iv);
      }
    }
    result.push(cipher.update(data));
    result.push(cipher.final());
    return Buffer.concat(result);
  }
}
