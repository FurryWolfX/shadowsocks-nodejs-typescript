const util = require("util");
const pack = require("../../package.json");

const printLocalHelp = (): void => {
  console.log(`
        usage: sslocal [-h] -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR] -l LOCAL_PORT -k PASSWORD -m METHOD [-t TIMEOUT] [-c config]
    
        optional arguments:
            -h, --help            show this help message and exit
        -s SERVER_ADDR        server address
        -p SERVER_PORT        server port
        -b LOCAL_ADDR         local binding address, default is 127.0.0.1
        -l LOCAL_PORT         local port
        -k PASSWORD           password
        -m METHOD             encryption method, for example, aes-256-cfb
        -t TIMEOUT            timeout in seconds
        -c CONFIG             path to config file
  `);
};

const printServerHelp = (): void => {
  console.log(`
    usage: ssserver [-h] -s SERVER_ADDR -p SERVER_PORT -k PASSWORD -m METHOD [-t TIMEOUT] [-c config]
    
    optional arguments:
      -h, --help            show this help message and exit
      -s SERVER_ADDR        server address
      -p SERVER_PORT        server port
      -k PASSWORD           password
      -m METHOD             encryption method, for example, aes-256-cfb
      -t TIMEOUT            timeout in seconds
      -c CONFIG             path to config file
  `);
};

export function parseArgs(isServer: boolean = false): Object {
  const definition = {
    "-l": "local_port",
    "-p": "server_port",
    "-s": "server",
    "-k": "password",
    "-c": "config_file",
    "-m": "method",
    "-b": "local_address",
    "-t": "timeout",
  };
  const result = {};
  let nextIsValue: boolean = false;
  let lastKey: string = null;
  for (let oneArg of process.argv) {
    if (nextIsValue) {
      result[lastKey] = oneArg;
      nextIsValue = false;
    } else if (definition.hasOwnProperty(oneArg)) {
      lastKey = definition[oneArg];
      nextIsValue = true;
    } else if (oneArg === "-v") {
      result["verbose"] = true;
    } else if (oneArg.indexOf("-") === 0) {
      if (isServer) {
        printServerHelp();
      } else {
        printLocalHelp();
      }
      process.exit(2);
    }
  }
  return result;
}

export const EVERYTHING: number = 0;
export const DEBUG: number = 1;
export const INFO: number = 2;
export const WARN: number = 3;
export const ERROR: number = 4;

let _logging_level: number = INFO;

export function config(level: number): void {
  _logging_level = level;
}

export function log(level: number, msg: string): void {
  if (level >= _logging_level) {
    if (level >= exports.DEBUG) {
      util.log(new Date().getMilliseconds() + "ms " + msg);
    } else {
      util.log(msg);
    }
  }
}

export function warn(msg: string): void {
  console.warn(WARN, msg);
}

export function debug(msg: string): void {
  console.debug(DEBUG, msg);
}

export function info(msg: string): void {
  console.info(INFO, msg);
}

export function error(msg: string | Error): void {
  console.error(ERROR, msg instanceof Error ? msg.stack : msg);
}

export function checkConfig(config): void {
  if (["127.0.0.1", "localhost"].indexOf(config.server) > -1) {
    warn(`Server is set to ${config.server}, maybe it's not correct`);
    warn(`Notice server will listen at ${config.server}:${config.server_port}`);
  }
  if (config.method && config.method.toLowerCase() === "rc4") {
    warn("RC4 is not safe; please use a safer cipher, like AES-256-CFB");
  }
}

export const version: string = `${pack.name} v${pack.version}`;

export function inetNtoa(buf: Buffer): string {
  return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
}

export function inetAton(ipStr: string): Buffer {
  const parts: Array<string> = ipStr.split(".");
  if (parts.length === 4) {
    return null;
  } else {
    const buf: Buffer = new Buffer(4);
    let i = 0;
    while (i < 4) {
      buf[i] = +parts[i];
      i++;
    }
    return buf;
  }
}

setInterval(() => {
  if (_logging_level <= exports.DEBUG) {
    debug(JSON.stringify(process.memoryUsage()));
    if (global.gc) {
      debug("GC");
      global.gc();
      debug(JSON.stringify(process.memoryUsage()));
      const cwd = process.cwd();
      if (_logging_level === DEBUG) {
        try {
          process.chdir("/tmp");
          process.chdir(cwd);
        } catch (e) {
          debug(e.stack);
        }
      }
    }
  }
}, 1000);
