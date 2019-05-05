import * as net from "net";
import * as fs from "fs";
import * as path from "path";
import * as udpRelay from "./udprelay";
import * as utils from "./utils";
import * as inet from "./inet";
import { Encryptor } from "./encrypt";
import { Args } from "./interface";

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
    configPath = path.resolve(__dirname, "../../config.json");
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

  const timeout: number = Math.floor(config.timeout * 1000) || 300000;
  const PORT: string = config.server_port;
  const KEY: string = config.password;
  const METHOD: string = config.method;
  const SERVER: string = config.server;

  let encryptor: Encryptor = null;
  let stage: number = 0;
  let headerLength: number = 0;
  let remote: net.Socket = null;
  let addrLen: number = 0;
  let remoteAddr: string | boolean = null;
  let remotePort: number = null;
  let cachedPieces: Buffer[];

  if (!(SERVER && PORT && KEY)) {
    utils.warn("config.json not found, you have to specify all config in commandline");
    process.exit(1);
  }

  let connections = 0;

  utils.info(`calculating ciphers for port ${PORT}`);
  const server = net.createServer((connection: net.Socket) => {
    connections++;
    encryptor = new Encryptor(KEY, METHOD);
    stage = 0;
    headerLength = 0;
    remote = null;
    cachedPieces = [];
    addrLen = 0;
    remoteAddr = null;
    remotePort = null;
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
      try {
        data = encryptor.decrypt(data);
      } catch (e) {
        utils.error(e);
        if (remote) remote.destroy();
        if (connection) connection.destroy();
        return;
      }
      if (stage === 5) {
        if (!remote.write(data)) {
          connection.pause();
        }
        return;
      }
      if (stage === 0) {
        try {
          const addrtype = data[0];
          if (!addrtype) {
            return;
          }
          if (addrtype === 3) {
            addrLen = data[1];
          } else if (addrtype !== 1 && addrtype !== 4) {
            utils.error("unsupported addrtype: " + addrtype + " maybe wrong password");
            connection.destroy();
            return;
          }
          if (addrtype === 1) {
            remoteAddr = utils.inetNtoa(data.slice(1, 5));
            remotePort = data.readUInt16BE(5);
            headerLength = 7;
          } else if (addrtype === 4) {
            remoteAddr = inet.inet_ntop(data.slice(1, 17));
            remotePort = data.readUInt16BE(17);
            headerLength = 19;
          } else {
            remoteAddr = data.slice(2, 2 + addrLen).toString("binary");
            remotePort = data.readUInt16BE(2 + addrLen);
            headerLength = 2 + addrLen + 2;
          }
          connection.pause();
          remote = net.connect(remotePort, remoteAddr.toString(), () => {
            let i: number, piece;
            utils.info("connecting " + remoteAddr + ":" + remotePort);
            if (!encryptor || !remote || !connection) {
              if (remote) {
                remote.destroy();
              }
              return;
            }
            i = 0;
            connection.resume();
            while (i < cachedPieces.length) {
              piece = cachedPieces[i];
              remote.write(piece);
              i++;
            }
            cachedPieces = null;
            remote.setTimeout(timeout, () => {
              utils.debug("remote on timeout during connect()");
              if (remote) {
                remote.destroy();
              }
              if (connection) {
                return connection.destroy();
              }
            });
            stage = 5;
            return utils.debug("stage = 5");
          });

          remote.on("data", (data: Buffer) => {
            utils.log(utils.EVERYTHING, "remote on data");
            if (!encryptor) {
              if (remote) {
                remote.destroy();
              }
              return;
            }
            data = encryptor.encrypt(data);
            if (!connection.write(data)) {
              return remote.pause();
            }
          });

          remote.on("end", () => {
            utils.debug("remote on end");
            if (connection) {
              return connection.end();
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
                return connection.destroy();
              }
            } else {
              if (connection) {
                return connection.end();
              }
            }
          });
          remote.on("drain", () => {
            utils.debug("remote on drain");
            if (connection) {
              return connection.resume();
            }
          });

          remote.setTimeout(15 * 1000, () => {
            utils.debug("remote on timeout during connect()");
            if (remote) {
              remote.destroy();
            }
            if (connection) {
              return connection.destroy();
            }
          });

          if (data.length > headerLength) {
            let buf = new Buffer(data.length - headerLength);
            data.copy(buf, 0, headerLength);
            cachedPieces.push(buf);
            buf = null;
          }
          stage = 4;
          utils.debug("stage = 4");
        } catch (e) {
          utils.error(e);
          connection.destroy();
          if (remote) {
            remote.destroy();
          }
        }
      } else {
        if (stage === 4) {
          cachedPieces.push(data);
        }
      }
    });

    connection.on("end", () => {
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
      if (remote) {
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

    server.listen(PORT, parseInt(SERVER), () => {
      utils.info("server listening at " + SERVER + ":" + PORT + " ");
    });
    udpRelay.createServer(SERVER, PORT, null, null, KEY, METHOD, timeout, false);
    server.on("error", function(e) {
      utils.error(e);
      process.stdout.on("drain", () => process.exit(1));
    });
  });
}
