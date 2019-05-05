import * as net from "net";
import * as fs from "fs";
import * as path from "path";
import * as udpRelay from "./udprelay";
import * as utils from "./utils";
import * as inet from "./inet";
import { Encryptor } from "./encrypt";
import { Socket } from "dgram";
import { AddressInfo, Server } from "net";
import { Args } from "./interface";

let connections: number = 0;

export function createServer(serverAddr, serverPort, port, key, method, timeout, local_address = "127.0.0.1"): Server {
  const udpServer: Socket = udpRelay.createServer(
    local_address,
    port,
    serverAddr,
    serverPort,
    key,
    method,
    timeout,
    true,
  );
  const getServer = (): [string, number] => {
    let aPort: number = <number>serverPort;
    let aServer: string = <string>serverAddr;
    if (serverPort instanceof Array) {
      // support config like "server_port": [8081, 8082]
      aPort = serverPort[Math.floor(Math.random() * serverPort.length)];
    }
    if (serverAddr instanceof Array) {
      // support config like "server": ["123.123.123.1", "123.123.123.2"]
      aServer = serverAddr[Math.floor(Math.random() * serverAddr.length)];
    }
    const r = /^([^:]*)\:(\d+)$/.exec(aServer);
    // support config like "server": "123.123.123.1:8381"
    // or "server": ["123.123.123.1:8381", "123.123.123.2:8381", "123.123.123.2:8382"]
    if (r) {
      aServer = r[1];
      aPort = +r[2];
    }
    return [aServer, aPort];
  };

  const server: Server = net.createServer(connection => {
    connections++;
    let connected: boolean = true;
    let encryptor: Encryptor = new Encryptor(key, method);
    let stage: number = 0;
    let headerLength: number = 0;
    let remote: net.Socket = null;
    let addrLen: number = 0;
    let remoteAddr: string | boolean = null;
    let remotePort: number = null;
    let addrToSend: string = "";

    utils.debug(`connections: ${connections}`);
    const clean = () => {
      utils.debug(`clean`);
      connections--;
      remote = null;
      connection = null;
      encryptor = null;
      utils.debug(`connections: ${connections}`);
    };
    connection.on("data", data => {
      utils.log(utils.EVERYTHING, "connection on data");
      if (stage === 5) {
        // pipe sockets
        data = encryptor.encrypt(data);
        if (!remote.write(data)) {
          connection.pause();
        }
        return;
      }
      if (stage === 0) {
        const tempBuf = new Buffer(2);
        tempBuf.write("\u0005\u0000", 0);
        connection.write(tempBuf);
        stage = 1;
        utils.debug("stage = 1");
        return;
      }
      if (stage === 1) {
        try {
          /*
          # +----+-----+-------+------+----------+----------+
          # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
          # +----+-----+-------+------+----------+----------+
          # | 1  |  1  | X'00' |  1   | Variable |    2     |
          # +----+-----+-------+------+----------+----------+
          */
          // cmd and addrtype
          const cmd = data[1];
          const addrtype = data[3];
          if (cmd === 1) {
            // TCP
          } else if (cmd === 3) {
            // UDP
            utils.info(`UDP assc request from ${connection.localAddress}:${connection.localPort}`);
            const reply = new Buffer(10);
            reply.write("\u0005\u0000\u0000\u0001", 0, 4, "binary");
            utils.debug(connection.localAddress);
            utils.inetAton(connection.localAddress).copy(reply, 4);
            reply.writeUInt16BE(connection.localPort, 8);
            connection.write(reply);
            stage = 10;
          } else {
            utils.error("unsupported cmd: " + cmd);
            const reply = new Buffer("\u0005\u0007\u0000\u0001", "binary");
            connection.end(reply);
            return;
          }
          if (addrtype === 3) {
            addrLen = data[4];
          } else if (addrtype !== 1 && addrtype !== 4) {
            utils.error("unsupported addrtype: " + addrtype);
            connection.destroy();
            return;
          }
          addrToSend = data.slice(3, 4).toString("binary");
          // read address and port
          if (addrtype === 1) {
            remoteAddr = utils.inetNtoa(data.slice(4, 8));
            addrToSend += data.slice(4, 10).toString("binary");
            remotePort = data.readUInt16BE(8);
            headerLength = 10;
          } else if (addrtype === 4) {
            remoteAddr = inet.inet_ntop(data.slice(4, 20));
            addrToSend += data.slice(4, 22).toString("binary");
            remotePort = data.readUInt16BE(20);
            headerLength = 22;
          } else {
            remoteAddr = data.slice(5, 5 + addrLen).toString("binary");
            addrToSend += data.slice(4, 5 + addrLen + 2).toString("binary");
            remotePort = data.readUInt16BE(5 + addrLen);
            headerLength = 5 + addrLen + 2;
          }
          if (cmd === 3) {
            utils.info("UDP assc: " + remoteAddr + ":" + remotePort);
            return;
          }
          let buf: Buffer = new Buffer(10);
          buf.write("\u0005\u0000\u0000\u0001", 0, 4, "binary");
          buf.write("\u0000\u0000\u0000\u0000", 4, 4, "binary");
          // 2222 can be any number between 1 and 65535
          buf.writeInt16BE(2222, 8);
          connection.write(buf);
          // connect remote server
          let [aServer, aPort] = getServer();
          utils.info(`connecting ${aServer}:${aPort}`);
          const remote = net.connect(aPort, aServer, () => {
            if (remote) {
              remote.setNoDelay(true);
            }
            stage = 5;
            utils.debug("stage = 5");
          });
          remote.on("data", data => {
            if (!connected) {
              return;
            }
            utils.log(utils.EVERYTHING, "remote on data");
            try {
              if (encryptor) {
                data = encryptor.decrypt(data);
                if (!connection.write(data)) {
                  remote.pause();
                }
              } else {
                remote.destroy();
              }
            } catch (e) {
              utils.error(e);
              if (remote) {
                remote.destroy();
              }
              if (connection) {
                connection.destroy();
              }
            }
          });
          remote.on("end", () => {
            utils.debug("remote on end");
            if (connection) {
              connection.end();
            }
          });
          remote.on("error", e => {
            utils.debug("remote on error");
            return utils.error("remote " + remoteAddr + ":" + remotePort + " error: " + e);
          });
          remote.on("close", had_error => {
            utils.debug("remote on close:" + had_error);
            if (had_error) {
              if (connection) {
                connection.destroy();
              }
            } else {
              if (connection) {
                connection.end();
              }
            }
          });
          remote.on("drain", () => {
            utils.debug("remote on drain");
            if (connection) {
              connection.resume();
            }
          });

          remote.setTimeout(timeout, () => {
            utils.debug("remote on timeout");
            if (remote) {
              remote.destroy();
            }
            if (connection) {
              connection.destroy();
            }
          });

          let addrToSendBuf = new Buffer(addrToSend, "binary");
          addrToSendBuf = encryptor.encrypt(addrToSendBuf);
          remote.setNoDelay(false);
          remote.write(addrToSendBuf);

          if (data.length > headerLength) {
            buf = new Buffer(data.length - headerLength);
            data.copy(buf, 0, headerLength);
            const piece = encryptor.encrypt(buf);
            remote.write(piece);
          }

          stage = 4;
          utils.debug("stage = 4");
        } catch (e) {
          utils.error(e);
          if (connection) {
            connection.destroy();
          }
          if (remote) {
            remote.destroy();
          }
          clean();
        }
      }
      if (stage === 4) {
        if (!remote) {
          if (connection) {
            connection.destroy();
          }
          return;
        }
        data = encryptor.encrypt(data);
        remote.setNoDelay(true);
        if (!remote.write(data)) {
          connection.pause();
        }
      }
    });
    connection.on("end", () => {
      connected = false;
      utils.debug("connection on end");
      if (remote) {
        remote.end();
      }
    });
    connection.on("error", e => {
      utils.debug("connection on error");
      utils.error("local error: " + e);
    });
    connection.on("close", had_error => {
      connected = false;
      utils.debug("connection on close:" + had_error);
      if (had_error) {
        if (remote) {
          remote.destroy();
        }
      } else {
        if (remote) {
          remote.end();
        }
      }
      clean();
    });
    connection.on("drain", () => {
      utils.debug("connection on drain");
      if (remote && stage === 5) {
        remote.resume();
      }
    });
    connection.setTimeout(timeout, () => {
      utils.debug("connection on timeout");
      if (remote) {
        remote.destroy();
      }
      if (connection) {
        connection.destroy();
      }
    });

    if (local_address) {
      server.listen(port, local_address, () => {
        const addressInfo: AddressInfo = <AddressInfo>server.address();
        utils.info("local listening at " + addressInfo.address + ":" + port);
      });
    } else {
      server.listen(port, () => {
        utils.info("local listening at 0.0.0.0:" + port);
      });
    }
    server.on("error", e => {
      utils.error(e);
    });
    server.on("close", () => {
      udpServer.close();
    });
  });

  return server;
}

export function main() {
  console.log(utils.version);
  let configFromArgs: Args = utils.parseArgs();
  let configPath: string = "config.json";
  let config: Args;
  if (configFromArgs.config_file) {
    configPath = configFromArgs.config_file;
  }
  if (!fs.existsSync(configPath)) {
    configPath = path.resolve(__dirname, "config.json");
  }
  if (!fs.existsSync(configPath)) {
    configPath = path.resolve(__dirname, "../config.json");
  }
  if (!fs.existsSync(configPath)) {
    configPath = null;
  }

  if (configPath) {
    utils.info("loading config from " + configPath);
    let configContent: Buffer = fs.readFileSync(configPath);
    try {
      config = JSON.parse(configContent.toString());
    } catch (e) {
      utils.error("found an error in config.json: " + e.message);
      process.exit(1);
    }
  } else {
    config = {};
  }

  for (let k in configFromArgs) {
    config[k] = configFromArgs[k];
  }
  if (config.verbose) {
    utils.config(utils.DEBUG);
  }

  utils.checkConfig(config);
  const SERVER = config.server;
  const REMOTE_PORT = config.server_port;
  const PORT = config.local_port;
  const KEY = config.password;
  const METHOD = config.method;
  const local_address = config.local_address;
  if (!(SERVER && REMOTE_PORT && PORT && KEY)) {
    utils.warn("config.json not found, you have to specify all config in commandline");
    process.exit(1);
  }
  const timeout = Math.floor(config.timeout * 1000) || 600000;
  const s = createServer(SERVER, REMOTE_PORT, PORT, KEY, METHOD, timeout, local_address);
  return s.on("error", e => {
    process.stdout.on("drain", function() {
      process.exit(1);
    });
  });
}
