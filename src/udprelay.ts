import * as dgram from "dgram";
import * as net from "net";
import * as utils from "./utils";
import * as inet from "./inet";
import * as encryptor from "./encrypt";
import Timeout = NodeJS.Timeout;
import { Socket, SocketType } from "dgram";
import { AddressInfo } from "net";

class LRUCache {
  timeout: number;
  interval: Timeout;
  sweepInterval: number;
  dict: Object = {};

  constructor(timeout: number, sweepInterval: number) {
    this.timeout = timeout;
    this.sweepInterval = sweepInterval;
    this.interval = setInterval(() => this.sweep(), sweepInterval);
  }

  setItem(key: string, value: Socket): void {
    const cur: [number, number] = process.hrtime();
    this.dict[key] = [value, cur];
  }

  getItem(key: string): Socket {
    const v: [Socket, [number, number]] = this.dict[key];
    if (v) {
      v[1] = process.hrtime();
      return v[0];
    }
    return null;
  }

  delItem(key): void {
    delete this.dict[key];
  }

  destroy(): void {
    clearInterval(this.interval);
  }

  sweep(): void {
    utils.debug("sweeping");
    const dict: Object = this.dict;
    const keys: string[] = Object.keys(dict);
    let swept: number = 0;
    keys.forEach(k => {
      const v: [Socket, [number, number]] = dict[k];
      const diff: [number, number] = process.hrtime(v[1]);
      if (diff[0] < this.timeout * 0.001) {
        swept++;
        v[0].close();
        delete dict[k];
      }
    });
    utils.debug(`${swept} keys swept`);
  }
}

/*
SOCKS5 UDP Request
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

SOCKS5 UDP Response
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

shadowsocks UDP Request (before encrypted)
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+

shadowsocks UDP Response (before encrypted)
+------+----------+----------+----------+
| ATYP | DST.ADDR | DST.PORT |   DATA   |
+------+----------+----------+----------+
|  1   | Variable |    2     | Variable |
+------+----------+----------+----------+

shadowsocks UDP Request and Response (after encrypted)
+-------+--------------+
|   IV  |    PAYLOAD   |
+-------+--------------+
| Fixed |   Variable   |
+-------+--------------+

HOW TO NAME THINGS
------------------
`dest` means destination server, which is from DST fields in the SOCKS5 request
`local` means local server of shadowsocks
`remote` means remote server of shadowsocks
`client` means UDP client, which is used for connecting, or the client that connects our server
`server` means UDP server, which is used for listening, or the server for our client to connect
*/
function encrypt(password: string, method: string, data: Buffer): Buffer {
  try {
    return encryptor.encryptAll(password, method, 1, data);
  } catch (e) {
    utils.error(e);
    return null;
  }
}

function decrypt(password: string, method: string, data: Buffer): Buffer {
  try {
    return encryptor.encryptAll(password, method, 0, data);
  } catch (e) {
    utils.error(e);
    return null;
  }
}

function parseHeader(data: Buffer, requestHeaderOffset: number): Array<any> {
  try {
    const addrtype: number = data[requestHeaderOffset];
    let destAddr: string | boolean, destPort: number, headerLength: number, addrLen: number;
    if (addrtype === 3) {
      addrLen = data[requestHeaderOffset + 1];
    } else if (addrtype !== 1 && addrtype !== 4) {
      utils.warn("unsupported addrtype: " + addrtype);
      return null;
    }

    if (addrtype === 1) {
      destAddr = utils.inetNtoa(data.slice(requestHeaderOffset + 1, requestHeaderOffset + 5));
      destPort = data.readUInt16BE(requestHeaderOffset + 5);
      headerLength = requestHeaderOffset + 7;
    } else if (addrtype === 4) {
      destAddr = inet.inet_ntop(data.slice(requestHeaderOffset + 1, requestHeaderOffset + 17));
      destPort = data.readUInt16BE(requestHeaderOffset + 17);
      headerLength = requestHeaderOffset + 19;
    } else {
      destAddr = data.slice(requestHeaderOffset + 2, requestHeaderOffset + 2 + addrLen).toString("binary");
      destPort = data.readUInt16BE(requestHeaderOffset + 2 + addrLen);
      headerLength = requestHeaderOffset + 2 + addrLen + 2;
    }
    return [addrtype, destAddr, destPort, headerLength];
  } catch (e) {
    utils.error(e);
    return null;
  }
}

export function createServer(
  listenAddr,
  listenPort,
  remoteAddr,
  remotePort,
  password,
  method,
  timeout,
  isLocal,
): Socket {
  let udpTypeToListen: SocketType;
  if (!listenAddr) {
    udpTypeToListen = "udp4";
  } else {
    const listenIPType = net.isIP(listenAddr);
    if (listenIPType === 6) {
      udpTypeToListen = "udp6";
    } else {
      udpTypeToListen = "udp4";
    }
  }

  const server: Socket = dgram.createSocket(udpTypeToListen);
  const clients: LRUCache = new LRUCache(timeout, 10 * 1000);
  const clientKey = (localAddr, localPort, destAddr, destPort): string => {
    return `${localAddr}:${localPort}:${destAddr}:${destPort}`;
  };
  server.on("message", (data, rinfo) => {
    // Parse request
    let requestHeaderOffset = 0;
    let sendDataOffset, serverAddr, serverPort;
    let serverIPBuf, responseHeader;
    if (isLocal) {
      requestHeaderOffset = 3;
      const frag = data[2];
      if (frag !== 0) {
        utils.debug(`frag:${frag}`);
        utils.warn("drop a message since frag is not 0");
        return;
      } else {
        // on remote, client to server
        data = decrypt(password, method, data);
        if (!data) {
          // drop
          return;
        }
      }
      let headerResult = parseHeader(data, requestHeaderOffset);
      if (headerResult === null) {
        // drop
        return;
      }
      let [addrtype, destAddr, destPort, headerLength] = headerResult;
      if (isLocal) {
        sendDataOffset = requestHeaderOffset;
        [serverAddr, serverPort] = [remoteAddr, remotePort];
      } else {
        sendDataOffset = headerLength;
        [serverAddr, serverPort] = [destAddr, destPort];
      }
      const key = clientKey(rinfo.address, rinfo.port, destAddr, destPort);
      let client: Socket = clients.getItem(key);
      if (!client) {
        // Create IPv6 UDP socket if serverAddr is an IPv6 address
        const clientUdpType = net.isIP(serverAddr);
        if (clientUdpType === 6) {
          client = dgram.createSocket("udp6");
        } else {
          client = dgram.createSocket("udp4");
        }
        clients.setItem(key, client);
        client.on("message", (data1, rinfo1) => {
          let data2;
          if (!isLocal) {
            // on remote, server to client
            // append shadowsocks response header
            // TODO: support receive from IPv6 addr
            utils.debug(`UDP recv from ${rinfo1.address}:${rinfo1.port}`);
            serverIPBuf = utils.inetAton(rinfo1.address);
            responseHeader = new Buffer(7);
            responseHeader.write("\x01", 0);
            serverIPBuf.copy(responseHeader, 1, 0, 4);
            responseHeader.writeUInt16BE(rinfo1.port, 5);
            data2 = Buffer.concat([responseHeader, data1]);
            data2 = encrypt(password, method, data2);
            if (!data2) {
              // drop
              return;
            }
          } else {
            // on local, server to client
            // append socks5 response header
            responseHeader = new Buffer("\x00\x00\x00");
            data1 = decrypt(password, method, data1);
            if (!data1) {
              // drop
              return;
            }
            headerResult = parseHeader(data1, 0);
            if (!headerResult) {
              // drop
              return;
            }
            [addrtype, destAddr, destPort, headerLength] = headerResult;
            utils.debug(`UDP recv from ${destAddr}:${destPort}`);
            data2 = Buffer.concat([responseHeader, data1]);
          }
          server.send(data2, 0, data2.length, rinfo.port, rinfo.address, (err, bytes) => {
            utils.debug("remote to local sent");
          });
        });

        client.on("error", err => {
          utils.debug(`UDP client error: ${err}`);
        });

        client.on("close", err => {
          utils.debug(`UDP client close`);
          clients.delItem(key);
        });
      }
      utils.debug(`pairs: ${Object.keys(clients.dict).length}`);
      let dataToSend = data.slice(sendDataOffset, data.length);
      if (isLocal) {
        // on local, client to server
        dataToSend = encrypt(password, method, dataToSend);
        if (!dataToSend) {
          // drop
          return;
        }
      }
      utils.debug(`UDP send to ${destAddr}:${destPort}`);
      client.send(dataToSend, 0, dataToSend.length, serverPort, serverAddr, (err, bytes) => {
        utils.debug("local to remote sent");
      });
    }
  });

  server.on("listening", () => {
    const address: AddressInfo = <AddressInfo>server.address();
    utils.info("UDP server listening " + address.address + ":" + address.port);
  });

  server.on("close", () => {
    utils.info("UDP server closing");
    clients.destroy();
  });

  if (listenAddr) {
    server.bind(listenPort, listenAddr);
  } else {
    server.bind(listenPort);
  }

  return server;
}
