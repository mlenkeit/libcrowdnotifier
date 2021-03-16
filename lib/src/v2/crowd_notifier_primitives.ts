import {
  compare,
  crypto_box_keypair,
  crypto_box_seal,
  crypto_box_seal_open,
  IKeyPair,
  randombytes_buf,
} from 'libsodium-wrappers-sumo';
import {dec, enc, IEncryptedData,
  keyDer, keyGen, NONCE_LENGTH} from './ibe_primitives';
import mcl from 'mcl-wasm';
import {
  IEntryProof, ILocationData, IMasterTrace,
  IPreTrace, ITrace, ITraceProof,
} from './structs';
import {genId} from './helpers';


/**
 * Implements the cryptographic protocol in section B.1 of the
 * CrowdNotifier white paper.
 */

/**
 * Generate key pair for health authority.
 */
export function setupHA(): IKeyPair {
  return crypto_box_keypair();
}

/**
 * Creates the data necessary for a location owner.
 * @param pkh public key of the health authority
 * @param info public info of the location, e.g., name:location:room
 * @return the QRCodeContent to be printed in multiple QR codes
 */
export function genCode(pkh: Uint8Array, info: Uint8Array): ILocationData {
  const [mpkl, mskl] = keyGen();
  const [mpkha, mskha] = keyGen();
  const mpk = mcl.add(mpkl, mpkha);
  const nonce1 = randombytes_buf(NONCE_LENGTH);
  const nonce2 = randombytes_buf(NONCE_LENGTH);

  const ctxtha = crypto_box_seal(mskha.serialize(), pkh);

  const pEnt = {nonce1, nonce2};
  const mtr = {mpk, mskl, info, nonce1, nonce2, ctxtha};

  return {ent: mpk, pEnt, mtr};
}


/**
 * Creates a private record for the user to store in her phone.
 * @param ent as presented in the QRentry
 * @param pEnt as presented in the QRentry
 * @param info as presented in the QRentry
 * @param cnt count of hours since UNIX epoch
 * @param aux free data
 * @return user record to be stored
 */
export function scan(ent: mcl.G2,
    pEnt: IEntryProof,
    info: Uint8Array,
    cnt: number,
    aux: Uint8Array): IEncryptedData {
  const mpk = ent;
  const {nonce1, nonce2} = pEnt;
  const id = genId(info, cnt, nonce1, nonce2);
  return enc(mpk, id, aux);
}


/**
 * Generates an anonymous trace prior that can only be used by people
 * having scanned the QRentry code.
 * @param mtr master trace
 * @param cnt count of hours since UNIX epoch
 * @return tracing information prior and proof of tracing information
 */
export function genPreTrace(mtr: IMasterTrace, cnt: number):
    [IPreTrace, ITraceProof] {
  const {mpk, mskl, info, nonce1, nonce2, ctxtha} = mtr;
  const id = genId(info, cnt, nonce1, nonce2);
  const pskidl = keyDer(mskl, id);

  const ptr = {id,
    pskidl,
    ctxtha};

  // ctxtha is omitted here because the ITraceProof is always found with a
  // IPreTrace.
  const pTr = {
    mpk,
    nonce1,
    nonce2,
  };

  return [ptr, pTr];
}


/**
 * Generates an anonymous trace that can only be used by people
 * having scanned the QRentry code.
 * @param keys_ha key pair of health authority
 * @param ptr tracing information prior
 * @return trace information or undefined if
 * we fail to decrypted the pretrace data
 */
export function genTrace(keys_ha: IKeyPair, ptr: IPreTrace):
    (ITrace | undefined) {
  const {id, pskidl, ctxtha} = ptr;

  const mskh = new mcl.Fr();
  try {
    // libsodium requires both private and public key to decrypt ctxtha.
    const mskh_raw =
        crypto_box_seal_open(ctxtha,
            keys_ha.publicKey, keys_ha.privateKey);
    mskh.deserialize(mskh_raw);
  } catch (e) {
    return undefined;
  }
  const pskidha = keyDer(mskh, id);

  const skid = mcl.add(pskidl, pskidha);

  return {id, skid};
}


/**
 * Verify that a trace is valid.
 * @param info as presented in the QRentry
 * @param cnt count of hours since UNIX epoch
 * @param tr trace information
 * @param pTr proof of the trace information
 */
export function verifyTrace(info: Uint8Array,
    cnt: number,
    tr: ITrace,
    pTr: ITraceProof): boolean {
  const {id, skid} = tr;
  const {mpk, nonce1, nonce2} = pTr;

  if (compare(id, genId(info, cnt, nonce1, nonce2)) !== 0) {
    return false;
  }

  const msg_orig = randombytes_buf(NONCE_LENGTH);
  const ctxt = enc(mpk, id, msg_orig);
  const msg_dec = dec(id, skid, ctxt);
  if (msg_dec === undefined) {
    return false;
  }

  return compare(msg_orig, msg_dec) === 0;
}


/**
 * Tries to match a user record against a trace.
 * @param rec one of the user records created by scan
 * @param tr one of the traces received by the health authority
 * @return the data encrypted during the scan
 * if the record match the trace or undefined otherwise
 */
export function match(rec: IEncryptedData, tr: ITrace):
    (Uint8Array | undefined) {
  const {id, skid} = tr;
  return dec(id, skid, rec);
}
