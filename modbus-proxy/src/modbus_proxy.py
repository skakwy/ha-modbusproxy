# -*- coding: utf-8 -*-
#
# This file is part of the modbus-proxy project
#
# Copyright (c) 2020-2021 Tiago Coutinho
# Distributed under the GPLv3 license. See LICENSE for more info.


import asyncio
import pathlib
import argparse
import warnings
import contextlib
import logging.config
from urllib.parse import urlparse

__version__ = "0.6.8"


DEFAULT_LOG_CONFIG = {
    "version": 1,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)8s %(name)s: %(message)s"}
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"}
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}

log = logging.getLogger("modbus-proxy")


def parse_url(url):
    if "://" not in url:
        url = f"tcp://{url}"
    result = urlparse(url)
    if not result.hostname:
        url = result.geturl().replace("://", "://0")
        result = urlparse(url)
    return result


class Connection:
    def __init__(self, name, reader, writer):
        self.name = name
        self.reader = reader
        self.writer = writer
        self.log = log.getChild(name)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, tb):
        await self.close()

    @property
    def opened(self):
        return (
            self.writer is not None
            and not self.writer.is_closing()
            and not self.reader.at_eof()
        )

    async def close(self):
        if self.writer is not None:
            self.log.debug("closing connection...")
            try:
                # Give SMA devices time to finish their response
                await asyncio.sleep(0.1)
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as error:
                self.log.info("failed to close: %r", error)
            else:
                self.log.info("connection closed")
            finally:
                self.reader = None
                self.writer = None

    async def _write(self, data):
        self.log.debug("sending %d bytes: %r", len(data), data)
        self.writer.write(data)
        await self.writer.drain()
        # Small delay for SMA devices that need time to process requests
        await asyncio.sleep(0.01)  # 10ms delay

    async def write(self, data):
        try:
            await self._write(data)
        except Exception as error:
            self.log.error("writting error: %r", error)
            await self.close()
            return False
        return True

    async def _read(self):
        """Read ModBus TCP message with improved SMA device compatibility"""
        try:
            # Read header with timeout to prevent hanging
            header = await asyncio.wait_for(self.reader.readexactly(6), timeout=5.0)
            self.log.debug("Raw header bytes: %s", " ".join(f"{b:02x}" for b in header))
        except asyncio.TimeoutError:
            self.log.error("Timeout reading Modbus header")
            raise
        except asyncio.IncompleteReadError as error:
            self.log.error("Failed to read Modbus header: %r", error)
            raise
        except Exception as error:
            self.log.error("Error reading Modbus header: %r", error)
            raise
            
        # Modbus TCP header structure:
        # Byte 0-1: Transaction ID
        # Byte 2-3: Protocol ID (should be 0, but SMA might use non-zero)  
        # Byte 4-5: Length field (number of bytes following)
        transaction_id = int.from_bytes(header[0:2], "big")
        protocol_id = int.from_bytes(header[2:4], "big") 
        size = int.from_bytes(header[4:6], "big")
        
        self.log.debug("Modbus header - Transaction ID: %d, Protocol ID: %d, Length: %d", 
                      transaction_id, protocol_id, size)
        
        # SMA devices may use non-zero protocol IDs, so just warn instead of failing
        if protocol_id != 0:
            self.log.debug("Non-standard protocol ID: %d (SMA device behavior)", protocol_id)
            
        # Size field includes unit identifier and function code onwards,
        # but excludes the 6-byte MBAP header, so we need to read (size) more bytes
        if size > 0:
            # SMA devices can send larger responses than standard Modbus
            # Increase limit but still protect against obviously corrupted data
            if size > 2048:  # Much more generous limit for SMA devices
                self.log.error("Modbus message size too large: %d bytes. Full header: %r", size, header)
                self.log.error("Raw header bytes: %s", " ".join(f"{b:02x}" for b in header))
                # Try to read available data to see if it's just a parsing issue
                available_data = b""
                try:
                    # Try to read some data to see what's actually there
                    available_data = await asyncio.wait_for(self.reader.read(min(size, 1024)), timeout=2.0)
                    self.log.error("Available data sample: %s", " ".join(f"{b:02x}" for b in available_data[:50]))
                except Exception as read_error:
                    self.log.error("Could not read available data: %r", read_error)
                raise ValueError(f"Modbus message size too large: {size} bytes")
                
            try:
                # Use progressive reading for large payloads with timeout
                if size > 256:
                    self.log.debug("Large payload detected (%d bytes), using progressive read", size)
                    payload = b""
                    remaining = size
                    while remaining > 0:
                        chunk_size = min(remaining, 256)
                        chunk = await asyncio.wait_for(
                            self.reader.readexactly(chunk_size), 
                            timeout=3.0
                        )
                        payload += chunk
                        remaining -= len(chunk)
                        self.log.debug("Read chunk: %d bytes, remaining: %d", len(chunk), remaining)
                else:
                    payload = await asyncio.wait_for(
                        self.reader.readexactly(size), 
                        timeout=3.0
                    )
                    
                reply = header + payload
                self.log.debug("Successfully read %d byte payload", len(payload))
            except asyncio.TimeoutError:
                self.log.error("Timeout reading Modbus payload of %d bytes", size)
                raise
            except asyncio.IncompleteReadError as error:
                self.log.error("Failed to read Modbus payload of %d bytes: %r", size, error)
                self.log.error("Header was: %r", header)
                raise
        else:
            reply = header
            self.log.debug("Zero-length payload, using header only")
            
        self.log.debug("received complete message (%d bytes)", len(reply))
        return reply

    async def read(self):
        try:
            return await self._read()
        except asyncio.IncompleteReadError as error:
            if error.partial:
                self.log.error("reading error - incomplete read: %r (got %d bytes, expected %d)", 
                              error, len(error.partial), error.expected)
                # Log the partial data for debugging
                self.log.debug("partial data received: %r", error.partial)
            else:
                self.log.info("client closed connection")
            await self.close()
        except ValueError as error:
            # Handle our custom ValueError for oversized messages
            self.log.error("Protocol error: %r", error)
            await self.close()
        except Exception as error:
            self.log.error("reading error: %r", error)
            await self.close()


class Client(Connection):
    def __init__(self, reader, writer):
        peer = writer.get_extra_info("peername")
        super().__init__(f"Client({peer[0]}:{peer[1]})", reader, writer)
        self.log.debug("new client connection")


class ModBus(Connection):
    def __init__(self, config):
        modbus = config["modbus"]
        url = parse_url(modbus["url"])
        bind = parse_url(config["listen"]["bind"])
        super().__init__(f"ModBus({url.hostname}:{url.port})", None, None)
        self.host = bind.hostname
        self.port = 502 if bind.port is None else bind.port
        self.modbus_host = url.hostname
        self.modbus_port = url.port
        self.timeout = modbus.get("timeout", None)
        self.connection_time = modbus.get("connection_time", 0)
        self.server = None
        self.lock = asyncio.Lock()

    @property
    def address(self):
        if self.server is not None:
            return self.server.sockets[0].getsockname()

    async def open(self):
        self.log.info("connecting to modbus...")
        self.reader, self.writer = await asyncio.open_connection(
            self.modbus_host, self.modbus_port
        )
        self.log.info("connected!")

    async def connect(self):
        if not self.opened:
            await asyncio.wait_for(self.open(), self.timeout)
            if self.connection_time > 0:
                self.log.info("delay after connect: %s", self.connection_time)
                await asyncio.sleep(self.connection_time)

    async def write_read(self, data, attempts=3):  # Increased attempts for SMA
        async with self.lock:
            for i in range(attempts):
                try:
                    await self.connect()
                    self.log.debug("Attempt %d/%d: Sending request to modbus device", i + 1, attempts)
                    coro = self._write_read(data)
                    result = await asyncio.wait_for(coro, self.timeout)
                    self.log.debug("Successfully got response from modbus device")
                    return result
                except asyncio.IncompleteReadError as error:
                    self.log.error(
                        "write_read incomplete read error [%s/%s]: %r (got %d bytes, expected %d)", 
                        i + 1, attempts, error, len(error.partial) if error.partial else 0, error.expected
                    )
                    await self.close()
                    if i < attempts - 1:  # Not the last attempt
                        self.log.info("Retrying after incomplete read...")
                        await asyncio.sleep(0.5)  # Wait before retry
                    else:
                        raise
                except asyncio.TimeoutError as error:
                    self.log.error(
                        "write_read timeout error [%s/%s]: %r", i + 1, attempts, error
                    )
                    await self.close()
                    if i < attempts - 1:  # Not the last attempt
                        self.log.info("Retrying after timeout...")
                        await asyncio.sleep(1.0)  # Longer wait after timeout
                    else:
                        raise
                except ValueError as error:
                    # Protocol errors (like oversized messages) shouldn't be retried
                    self.log.error("Protocol error, not retrying: %r", error)
                    await self.close()
                    raise
                except Exception as error:
                    self.log.error(
                        "write_read error [%s/%s]: %r", i + 1, attempts, error
                    )
                    await self.close()
                    if i < attempts - 1:  # Not the last attempt
                        self.log.info("Retrying after error...")
                        await asyncio.sleep(0.3)
                    else:
                        raise

    async def _write_read(self, data):
        await self._write(data)
        return await self._read()

    async def handle_client(self, reader, writer):
        async with Client(reader, writer) as client:
            while True:
                # Read client request
                request = await client.read()
                if not request:
                    break
                    
                self.log.debug("Forwarding request to modbus device: %d bytes", len(request))
                
                # Forward to modbus device and get reply
                reply = await self.write_read(request)
                if not reply:
                    self.log.error("No reply from modbus device")
                    break
                    
                self.log.debug("Got reply from modbus device: %d bytes", len(reply))
                
                # Send reply back to client
                result = await client.write(reply)
                if not result:
                    self.log.error("Failed to send reply to client")
                    break
                    
                # Small delay to let SMA devices process the transaction
                await asyncio.sleep(0.02)  # 20ms delay between transactions

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port, start_serving=True
        )

    async def stop(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        await self.close()

    async def serve_forever(self):
        if self.server is None:
            await self.start()
        async with self.server:
            self.log.info("Ready to accept requests on %s:%d", self.host, self.port)
            await self.server.serve_forever()


def load_config(file_name):
    file_name = pathlib.Path(file_name)
    ext = file_name.suffix
    if ext.endswith("toml"):
        from toml import load
    elif ext.endswith("yml") or ext.endswith("yaml"):
        import yaml

        def load(fobj):
            return yaml.load(fobj, Loader=yaml.Loader)

    elif ext.endswith("json"):
        from json import load
    else:
        raise NotImplementedError
    with open(file_name) as fobj:
        return load(fobj)


def prepare_log(config, log_config_file=None):
    cfg = config.get("logging")
    if not cfg:
        if log_config_file:
            if log_config_file.endswith("ini") or log_config_file.endswith("conf"):
                logging.config.fileConfig(
                    log_config_file, disable_existing_loggers=False
                )
            else:
                cfg = load_config(log_config_file)
        else:
            cfg = DEFAULT_LOG_CONFIG
    if cfg:
        cfg.setdefault("version", 1)
        cfg.setdefault("disable_existing_loggers", False)
        logging.config.dictConfig(cfg)
    warnings.simplefilter("always", DeprecationWarning)
    logging.captureWarnings(True)
    if log_config_file:
        warnings.warn(
            "log-config-file deprecated. Use config-file instead", DeprecationWarning
        )
        if "logging" in config:
            log.warning("log-config-file ignored. Using config file logging")
    return log


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="ModBus proxy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config-file", default=None, type=str, help="config file"
    )
    parser.add_argument("-b", "--bind", default=None, type=str, help="listen address")
    parser.add_argument(
        "--modbus",
        default=None,
        type=str,
        help="modbus device address (ex: tcp://plc.acme.org:502)",
    )
    parser.add_argument(
        "--modbus-connection-time",
        type=float,
        default=0,
        help="delay after establishing connection with modbus before first request",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="modbus connection and request timeout in seconds",
    )
    parser.add_argument(
        "--log-config-file",
        default=None,
        type=str,
        help="log configuration file. By default log to stderr with log level = INFO",
    )
    options = parser.parse_args(args=args)

    if not options.config_file and not options.modbus:
        parser.exit(1, "must give a config-file or/and a --modbus")
    return options


def create_config(args):
    if args.config_file is None:
        assert args.modbus
    config = load_config(args.config_file) if args.config_file else {}
    prepare_log(config, args.log_config_file)
    log.info("Starting...")
    devices = config.setdefault("devices", [])
    if args.modbus:
        listen = {"bind": ":502" if args.bind is None else args.bind}
        devices.append(
            {
                "modbus": {
                    "url": args.modbus,
                    "timeout": args.timeout,
                    "connection_time": args.modbus_connection_time,
                },
                "listen": listen,
            }
        )
    return config


def create_bridges(config):
    return [ModBus(cfg) for cfg in config["devices"]]


async def start_bridges(bridges):
    coros = [bridge.start() for bridge in bridges]
    await asyncio.gather(*coros)


async def run_bridges(bridges, ready=None):
    async with contextlib.AsyncExitStack() as stack:
        coros = [stack.enter_async_context(bridge) for bridge in bridges]
        await asyncio.gather(*coros)
        await start_bridges(bridges)
        if ready is not None:
            ready.set(bridges)
        coros = [bridge.serve_forever() for bridge in bridges]
        await asyncio.gather(*coros)


async def run(args=None, ready=None):
    args = parse_args(args)
    config = create_config(args)
    bridges = create_bridges(config)
    await run_bridges(bridges, ready=ready)


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.warning("Ctrl-C pressed. Bailing out!")


if __name__ == "__main__":
    main()