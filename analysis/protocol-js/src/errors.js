// Error classes. Native error codes (negative ints) are kept on `.code` where they exist.

/** Native error codes seen in the decompiled code (native_transport.md §5.1, §6.3). */
export const NATIVE_ERR = Object.freeze({
  PROTOCOL: -4, // stream seq mismatch, bad inbound type, unresolvable mapping
  EVENT_TOO_LONG: -19, // editor event body > 16 bytes
  SYMBOL_NOT_FOUND: -21, // SymbolTable::LookupString failed
  TIMEOUT: -28, // RPC wait / stream heartbeat timeout
  CHANNEL_STOPPED: -35, // RSMC stopped with messages queued
  MESSAGE_TOO_BIG: -36, // RSMC QueueOutMessage: message > MTU-12
  REMOTE_DOWN: -37,
  EOF: -41,
});

/** Base class for everything thrown by this library. */
export class AmpProtocolError extends Error {
  constructor(message, code) {
    super(message);
    this.name = this.constructor.name;
    if (code !== undefined) this.code = code;
  }
}

/** A storage-writing command was requested without { confirmWrite: true }. */
export class WriteNotConfirmedError extends AmpProtocolError {}

/** Command refused locally because of the amp's firmware version (native gates, §9). */
export class FirmwareGateError extends AmpProtocolError {}

/** A response carried a negative i32 status. */
export class RpcStatusError extends AmpProtocolError {
  constructor(message, status) {
    super(message, status);
    this.status = status;
  }
}

/** A request or stream timed out (native -28). */
export class TimeoutError extends AmpProtocolError {
  constructor(message) {
    super(message, NATIVE_ERR.TIMEOUT);
  }
}

/** A name was not found in the symbol table (native -21). */
export class SymbolNotFoundError extends AmpProtocolError {
  constructor(name) {
    super(`symbol not in table: ${JSON.stringify(name)}`, NATIVE_ERR.SYMBOL_NOT_FOUND);
    this.symbol = name;
  }
}

/** Editor (group, param) has no DSP address (native returns -4). */
export class MappingError extends AmpProtocolError {
  constructor(message) {
    super(message, NATIVE_ERR.PROTOCOL);
  }
}
