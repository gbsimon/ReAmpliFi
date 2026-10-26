// Firmware guardrail (PLAN.md §5.8). ALLOW-LIST, not deny-list.
//
// HARD RULE for this project: firmware update / flash / DFU / the updater service mode are out
// of scope permanently. Nothing here (or anywhere in src/) implements them. This module is the
// single place where those words may appear: a test greps the rest of src/ for
// update|flash|dfu|UPDATER and fails on a hit.
//
// Enforced inside AmpSession before any bytes are encoded (and again by the low-level encoders
// for storage writes):
//   - streams: only 0x2002→0x03ED (editor) and 0x2003→0x03EF (librarian / device info);
//   - service-mode words on 0x03EF: only 1 (LIBRARIAN) and 2 (DEVICE_INFO). Word 0 is the
//     UPDATER mode (native_transport.md §4.2, §12) → FirmwareGuardError;
//   - port modes: only 2, 3, 4. Mode 1 (kUpdateMode) → FirmwareGuardError;
//   - editor cmds 1–17, 20, 21 free; 18/19/22 (persistent settings) need { confirmWrite: true };
//   - librarian cmds 1–8, 10, 11, 14 free; 12 with idx 0xFFFFFFFF (edit buffer) free;
//     9 / 12 (idx ≠ 0xFFFFFFFF) / 15 need { confirmWrite: true };
//   - anything else throws (e.g. librarian 13 LoadHardwarePreset, unused by the official app);
//   - amps whose device-info firmwareRevision is below 0x01000000 are refused (the official
//     app would force a firmware update there; we never offer one).

import { AmpProtocolError, WriteNotConfirmedError } from './errors.js';

/** Thrown for anything outside the allow-list, in particular the updater paths. */
export class FirmwareGuardError extends AmpProtocolError {}
/** Backwards-compatible alias. */
export const AvoidError = FirmwareGuardError;

/** Amp firmware too old: the official app would force a firmware update; we refuse to connect. */
export class UnsupportedFirmwareError extends FirmwareGuardError {}

/** Allowed service-mode words (L6BspMsgPort_Amplifi::changeMode 0xa1d5e). Word 0 deliberately absent. */
export const SERVICE_MODE = Object.freeze({ LIBRARIAN: 1, DEVICE_INFO: 2 });

/** Allowed ePortMode values (TranslateePortMode 0xa1d2a). Mode 1 deliberately absent. */
export const PORT_MODE = Object.freeze({ EDITOR: 2, LIBRARIAN: 3, DEVICE_INFO: 4 });

/** Allowed (local → remote) stream pairs. */
export const ALLOWED_STREAMS = Object.freeze([
  { local: 0x2002, remote: 0x03ed, service: 'editor' },
  { local: 0x2003, remote: 0x03ef, service: 'librarian' },
]);

const EDIT_BUFFER = 0xffffffff;

/**
 * Allow-list of command ids per service.
 * 'free' = always allowed; 'write' = needs { confirmWrite: true };
 * 'editBufferOrWrite' = free when index is the edit buffer, otherwise needs confirmWrite.
 */
export const COMMAND_ALLOW_LIST = Object.freeze({
  editor: Object.freeze({
    1: 'free', 2: 'free', 3: 'free', 4: 'free', 5: 'free', 6: 'free', 7: 'free', 8: 'free',
    9: 'free', 10: 'free', 11: 'free', 12: 'free', 13: 'free', 14: 'free', 15: 'free', 16: 'free',
    17: 'free', 18: 'write', 19: 'write', 20: 'free', 21: 'free', 22: 'write',
  }),
  librarian: Object.freeze({
    1: 'free', 2: 'free', 3: 'free', 4: 'free', 5: 'free', 6: 'free', 7: 'free', 8: 'free',
    9: 'write', 10: 'free', 11: 'free', 12: 'editBufferOrWrite', 14: 'free', 15: 'write',
  }),
});

/** Names that are on the AVOID list (documentation only; none of them is implemented). */
export const AVOID_LIST = Object.freeze([
  'service-mode word 0 (UPDATER) on stream 0x03EF',
  'ePortMode 1 (kUpdateMode)',
  'nativeStartFirmwareUpdate / nativeOpen mode 2 (FIRMWARE_UPDATE_MODE)',
  'L6AndroidNdkDevice::prepareForUpdating / startUpdate / forceFirmwareUpdate',
  'L6BspUpdateEngine::* and L6UUE::* (update engine), Checksum_Fletcher',
  'FirmwareServiceInterface*::PrepareForUpdate / ConvertToUpdater',
  'MsgPort_Stream_Abort (used only by the updater)',
]);

/** Raw firmwareRevision below which the official app forces an update (native_transport.md §7). */
export const MIN_SUPPORTED_FIRMWARE = 0x01000000;

/** Throws FirmwareGuardError unless `word` is 1 (LIBRARIAN) or 2 (DEVICE_INFO). */
export function assertServiceModeAllowed(word) {
  if (word === 0) {
    throw new FirmwareGuardError('refusing service-mode word 0 (UPDATER): firmware update paths are permanently out of scope');
  }
  if (word !== SERVICE_MODE.LIBRARIAN && word !== SERVICE_MODE.DEVICE_INFO) {
    throw new FirmwareGuardError(`refusing service-mode word ${word}: only 1 (LIBRARIAN) and 2 (DEVICE_INFO) are allowed`);
  }
}

/** Throws FirmwareGuardError unless `mode` is 2, 3 or 4. */
export function assertPortModeAllowed(mode) {
  if (mode === 1) throw new FirmwareGuardError('refusing port mode 1 (kUpdateMode): firmware update paths are permanently out of scope');
  if (!Object.values(PORT_MODE).includes(mode)) throw new FirmwareGuardError(`refusing unknown port mode ${mode}`);
}

/** Throws FirmwareGuardError unless (local, remote) is one of the two allowed streams. */
export function assertStreamAllowed(local, remote) {
  if (!ALLOWED_STREAMS.some((s) => s.local === local && s.remote === remote)) {
    throw new FirmwareGuardError(`refusing stream 0x${local.toString(16)}→0x${remote.toString(16)}: not on the allow-list`);
  }
}

/** Require { confirmWrite: true } for a command that writes the amp's stored data. */
export function assertWriteConfirmed(what, opts) {
  if (!opts || opts.confirmWrite !== true) {
    throw new WriteNotConfirmedError(`${what} writes the amp's stored data; pass { confirmWrite: true } to proceed`);
  }
}

/**
 * Allow-list check for one RPC command, done before encoding.
 * @param {'editor'|'librarian'} service
 * @param {number} cmdId
 * @param {{index?:number, confirmWrite?:boolean}} [opts] index = preset index for librarian 12
 */
export function assertCommandAllowed(service, cmdId, opts = {}) {
  const list = COMMAND_ALLOW_LIST[service];
  if (!list) throw new FirmwareGuardError(`unknown service ${service}`);
  const rule = list[cmdId];
  if (!rule) throw new FirmwareGuardError(`refusing ${service} command ${cmdId}: not on the allow-list`);
  if (rule === 'write') assertWriteConfirmed(`${service} command ${cmdId}`, opts);
  if (rule === 'editBufferOrWrite') {
    if (opts.index === undefined) throw new FirmwareGuardError(`${service} command ${cmdId} needs the target index for the guard check`);
    if (opts.index >>> 0 !== EDIT_BUFFER) assertWriteConfirmed(`${service} command ${cmdId} to slot ${opts.index}`, opts);
  }
}

/**
 * Refuse amps whose device-info firmwareRevision is below 0x01000000. We never offer an update.
 * @param {number} rawRevision
 */
export function assertFirmwareSupported(rawRevision) {
  if ((rawRevision >>> 0) < MIN_SUPPORTED_FIRMWARE) {
    throw new UnsupportedFirmwareError(
      `unsupported firmware 0x${(rawRevision >>> 0).toString(16).padStart(8, '0')} (< 0x01000000): ` +
        'the official app would force a firmware update here; this library never does. Refusing to connect.',
    );
  }
}
