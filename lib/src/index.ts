import * as v1 from './v1';
import * as v1_1 from './v1_1';
import {
  EntryProof,
  genCode,
  genPreTrace,
  genTrace,
  IEncryptedData,
  ILocationData,
  IOrganizerData,
  IOrganizerPublic,
  IMasterTrace,
  QRCodeContent,
  MasterTrace,
  match,
  baseG1, baseG2, genId,
  PreTrace,
  TraceProof,
  PreTraceWithProof,
  QRCodeEntry,
  QRCodeTrace,
  scan,
  setupHA,
  Trace,
  verifyTrace,
  waitReady,
} from './v2';
import {
  genOrgStatic,
  genOrgCode,
  genOrgInit,
  genOrgFollow,
} from './v2_1';
import {Log} from './log';
import mcl from 'mcl-wasm';
import sodium from 'libsodium-wrappers-sumo';

export interface IKeyPair {
    keyType: string;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}

export {
  // CrowdNotifierPrimitives
  setupHA, genCode, scan,
  genPreTrace, genTrace, verifyTrace, match,
  // Managed CrowdNotifier (v2.1)
  genOrgStatic, genOrgCode, genOrgFollow, genOrgInit,
  // Generic crypto primitives needed
  waitReady, IEncryptedData, baseG1, baseG2, genId,
  // Proto structures needed
  PreTraceWithProof, Trace, PreTrace, TraceProof,
  QRCodeTrace, QRCodeEntry, QRCodeContent, MasterTrace,
  EntryProof,
  // Structures
  ILocationData, IOrganizerData, IOrganizerPublic,
  IMasterTrace,
  // old versions of the protocol
  v1, v1_1,
  // beloved log-library
  Log,
  // mcl and sodium need to be exported from here, else
  // node will instantiate two versions and will fail.
  mcl, sodium,
};
