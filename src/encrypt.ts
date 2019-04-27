import { Cipher, Decipher, Hash } from "crypto";
import * as crypto from "crypto";
import mergeSort from "./mergeSort";

const int32Max: number = Math.pow(2, 32);
const cachedTables: Object = {}; // password: [encryptTable, decryptTable]
const bytes_to_key_results: Object = {};

export function getTable(key: string): Array<Array<any>> {
  if (cachedTables[key]) {
    return cachedTables[key];
  }
  console.log("calculating ciphers");
  let table: Array<any> = new Array(256);
  const decrypt_table: Array<any> = new Array(256);
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
    decrypt_table[table[i]] = i;
    ++i;
  }
  const result = [table, decrypt_table];
  cachedTables[key] = result;
  return result;
}

function substitute(table: Array<any>, buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    buf[i] = table[buf[i]];
  }
  return buf;
}

function EVP_BytesToKey(password: Buffer, key_len: number, iv_len: number): Array<Buffer> {
  if (bytes_to_key_results[`${password}:${key_len}:${iv_len}`]) {
    return bytes_to_key_results[`${password}:${key_len}:${iv_len}`];
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
  bytes_to_key_results[password.toString()] = [key, iv];
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

function create_rc4_md5_cipher(key, iv, op): Cipher | Decipher {
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
  iv_sent: boolean;
  cipher: Cipher | Decipher;
  decipher: Cipher | Decipher;
  encryptTable: any;
  decryptTable: any;
  cipher_iv: any;
  key: any;
  method: any;

  constructor(key, method) {
    this.iv_sent = false;
    this.key = key;
    this.method = method;
    if (this.method === "table") {
      this.method = null;
    }
    if (this.method) {
      this.cipher = this.get_cipher(this.key, this.method, 1, crypto.randomBytes(32));
    } else {
      [this.encryptTable, this.decryptTable] = getTable(this.key);
    }
  }

  get_cipher_len(method) {
    method = method.toLowerCase();
    return method_supported[method];
  }

  get_cipher(password: string, method: string, op: number, iv: any): Cipher | Decipher {
    method = method.toLowerCase();
    const passwordBuffer = new Buffer(password, "binary");
    const m = this.get_cipher_len(method);
    if (m) {
      const arr: Array<Buffer> = EVP_BytesToKey(passwordBuffer, m[0], m[1]);
      const key: Buffer = arr[0];
      const iv_: Buffer = arr[1];
      if (!iv) {
        iv = iv_;
      }
      if (op === 1) {
        this.cipher_iv = iv.slice(0, m[1]);
      }
      iv = iv.slice(0, m[1]);
      if (method === "rc4-md5") {
        return create_rc4_md5_cipher(key, iv, op);
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
      if (this.iv_sent) {
        return result;
      } else {
        this.iv_sent = true;
        return Buffer.concat([this.cipher_iv, result]);
      }
    } else {
      return substitute(this.encryptTable, buf);
    }
  }

  decrypt(buf: Buffer): Buffer {
    let decipher_iv: Buffer, decipher_iv_len: number, result: Buffer;
    if (this.method != null) {
      if (this.decipher == null) {
        decipher_iv_len = this.get_cipher_len(this.method)[1];
        decipher_iv = buf.slice(0, decipher_iv_len);
        this.decipher = this.get_cipher(this.key, this.method, 0, decipher_iv);
        result = this.decipher.update(buf.slice(decipher_iv_len));
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

export function encryptAll(password, method, op, data): Buffer {
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
      cipher = create_rc4_md5_cipher(key, iv, op);
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
