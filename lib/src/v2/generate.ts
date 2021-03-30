import {
  keyGen,
  keyDer,
  enc,
  dec
} from './ibe_primitives';
import {
  Log,
  waitReady
} from './../index';
import { 
  strict as assert
} from 'assert';
import fs from 'fs';
import mcl from 'mcl-wasm';

const log = new Log('generate');
log.info(`Starting at: ${new Date()}`);

const generateKeyPair = function(): [mcl.G2, mcl.Fr] {
  log.info('Generating key pair...')
  const [ mpk, msk ] = keyGen()
  log.info('Key pair generated.')
  const buffers = {
    mpk: Buffer.from(mpk.serialize()),
    msk: Buffer.from(msk.serialize())
  }
  const hex = {
    mpk: buffers.mpk.toString('hex'),
    msk: buffers.msk.toString('hex')
  }
  const base64 = {
    mpk: buffers.mpk.toString('base64'),
    msk: buffers.msk.toString('base64')
  }
  log.info('with hex encoding:')
  log.info('  mpk', hex.mpk)
  log.info('  msk', hex.msk)
  log.info('with base64 encoding:')
  log.info('  mpk', base64.mpk)
  log.info('  msk', base64.msk)

  return [ mpk, msk ]
}

const verifyKeyPairWithValidId = async (mpk: mcl.G2, msk: mcl.Fr) => {
  const msgStr = 'hello-world'
  const message = Buffer.from(msgStr, 'utf-8')
  const id = Buffer.from('my-venue-123', 'utf-8')
  // encrypt with public key:
  const encryptedData = enc(mpk, id, message)
  // decrypt with key derived for id:
  const skid = keyDer(msk, id)
  const decryptedData = dec(id, skid, encryptedData)
  // compare
  const actMsgStr = decryptedData ? Buffer.from(decryptedData).toString('utf-8') : undefined
  assert.strictEqual(actMsgStr, msgStr)
}

const verifyKeyPairWithFalseId = async (mpk: mcl.G2, msk: mcl.Fr) => {
  const msgStr = 'hello-world'
  const message = Buffer.from(msgStr, 'utf-8')
  const id = Buffer.from('my-venue-123', 'utf-8')
  const falseId = Buffer.from('some-other-venue-456', 'utf-8')
  // encrypt with public key:
  const encryptedData = enc(mpk, id, message)
  // decrypt with key derived for id:
  const skid = keyDer(msk, falseId)
  const decryptedData = dec(falseId, skid, encryptedData)
  // compare
  const actMsgStr = decryptedData ? Buffer.from(decryptedData).toString('utf-8') : undefined
  assert.strictEqual(actMsgStr, undefined)
}

async function main() {
  await waitReady();
  const [ mpk, msk ] = generateKeyPair()
  
  log.info('Verifying key pair...')
  await verifyKeyPairWithValidId(mpk, msk)
  await verifyKeyPairWithFalseId(mpk, msk)
  log.info('Key pair verified.');

  log.info('Writing key pair to disk as binaries...')
  fs.writeFileSync('mpk.bin', mpk.serialize())
  fs.writeFileSync('msk.bin', msk.serialize())
  log.info('Created mpk.bin and msk.bin.')

  log.info('Writing key pair to disk as base64...')
  fs.writeFileSync('mpk.base64', Buffer.from(mpk.serialize()).toString('base64'))
  fs.writeFileSync('msk.base64', Buffer.from(msk.serialize()).toString('base64'))
  log.info('Created mpk.base64 and msk.base64.')

  log.info('Done');
}


main().catch((e) => {
  log.panic(e);
});