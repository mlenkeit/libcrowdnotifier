import {
  genTrace,
  IEncryptedData, IKeyPair, MasterTrace,
  match,
  mcl,
  PreTraceWithProof, QRCodeContent,
  QRCodeEntry, QRCodeTrace,
  scan,
  setupHA,
  sodium,
  Trace,
  verifyTrace,
} from '@c4dt/libcrowdnotifier';
import {randomBytes} from 'crypto';
import {Organizer} from '../v2_1';
import {EntryProof, IMasterTrace, IOrganizerPublic} from '../../lib';

/**
 * The System package uses the crypto but only passes around
 * base64 encoded protobuf messages. This helps to
 * understand which fields need to be serialized / deserialized.
 *
 * Using one Location class is a special case of the more general
 * "managed room creation". For this reason, Location calls out
 * to the managed classes.
 *
 * But because the case described in the whitepaper is based on
 * the description of a Location, this is the 'system' described
 * here.
 */

/**
 * HealthAuthority wraps the calls for the health authority from
 * libcrowdnotifier namespace.
 */
export class HealthAuthority {
  public keyPair: IKeyPair;

  constructor(kp?: IKeyPair) {
    if (kp === undefined) {
      kp = setupHA();
    }
    this.keyPair = kp;
  };

  /**
     * In case of an infection notification, the
     * @param preTrace64 representation of preTrace
     * @param counts sent by the health authority
     */
  createTraceEntry(preTrace64: string, counts: string): string {
    const preTraceWithProof =
            PreTraceWithProof.decode(sodium.from_base64(preTrace64));
    const preTraceProto = preTraceWithProof.preTrace;
    const traceProofProto = preTraceWithProof.proof;
    const info = preTraceWithProof.info;

    const partialSecretKeyForIdentityOfLocation = new mcl.G1();
    partialSecretKeyForIdentityOfLocation
        .deserialize(preTraceProto.partialSecretKeyForIdentityOfLocation);
    const masterPublicKey = new mcl.G2();
    masterPublicKey.deserialize(traceProofProto.masterPublicKey);

    const preTrace = {
      id: preTraceProto.identity,
      ctxtha: preTraceProto.cipherTextHealthAuthority,
      pskidl: partialSecretKeyForIdentityOfLocation,
    };
    const traceProof = {
      mpk: masterPublicKey,
      nonce1: traceProofProto.nonce1,
      nonce2: traceProofProto.nonce2,
    };

    const count = parseInt(counts);
    const trace = genTrace(this.keyPair, preTrace);

    if (trace === undefined) {
      throw new Error('couldn\'t create a trace.');
    }
    if (!verifyTrace(info, count, trace, traceProof)) {
      throw new Error('Invalid trace.');
    }

    const traceProto = {
      identity: trace.id,
      secretKeyForIdentity: trace.skid.serialize(),
    };

    const traceSer = Trace.encode(Trace.create(traceProto)).finish();
    return sodium.to_base64(traceSer);
  }
}

/**
 * Location is used by a location owner to create the two QRCodes.
 */
export class Location {
  public organizer: Organizer;
  public room: Room;

  /**
   * This creates a new location QRCode.
   * @param authority
   * @param venueType
   * @param name
   * @param location
   * @param room
   */
  constructor(
      authority: (Organizer | Uint8Array),
      venueType: number,
      name: string,
      location: string,
      room: string,
  ) {
    if (authority instanceof Organizer) {
      this.organizer = authority;
    } else {
      this.organizer = Organizer.fromPassPhrase(authority,
          sodium.to_base64(randomBytes(32)));
    }
    this.room = Room.fromOrganizerPublic(this.organizer.data,
        venueType, name, location, room);
  }

  /**
   * preTrace is implemented as a static method,
   * because we suppose that the location owner doesn't have the
   * information necessary anywhere else than in the QRtrace code.
   *
   * TODO: add more than one count
   * @param qrTrace the string from the qrTrace code
   * @param counts currently only a string representing one count -
   * hours since the unix epoch.
   */
  static preTrace(qrTrace: string, counts: string): string {
    const count = parseInt(counts);
    const room = Room.fromQRTrace(qrTrace);
    return Organizer.fromQRTrace(qrTrace).preTrace(room, [count])[0];
  }


  /**
   * Returns the base64 encoded protobuf-message for the location owner.
   *
   * @param baseURL - anything - is ignored and removed afterwards.
   */
  getQRtrace(baseURL: string): string {
    const mtr = this.room.getMasterTraceRecord(this.organizer);

    const qrTrace = new QRCodeTrace({
      version: 2,
      masterTraceRecord: new MasterTrace({
        masterPublicKey: mtr.mpk.serialize(),
        masterSecretKeyLocation: mtr.mskl.serialize(),
        info: mtr.info,
        nonce1: mtr.nonce1,
        nonce2: mtr.nonce2,
        cipherTextHealthAuthority: mtr.ctxtha,
      }),
    });
    return `${baseURL}#` +
          `${sodium.to_base64(QRCodeTrace.encode(qrTrace).finish())}`;
  }


  /**
   * Returns the base64 encoded protobuf-message necessary for
   * visitors to register.
   *
   * @param baseURL - anything - is ignored and removed afterwards.
   */
  getQRentry(baseURL: string): string {
    return this.room.getQRentry(baseURL);
  }
}

/**
 * The user has zero or more instances of Visit in his phone.
 */
export class Visit {
    public identity = 'undefined';
    constructor(readonly data: IEncryptedData) {}

    static fromQRCode(
        qrCodeEntry: string,
        entryTime: number,
        diary?: boolean,
    ): Visit {
      const qrBase64 = qrCodeEntry.replace(/^.*#/, '');
      const qrEntry = QRCodeEntry.decode(sodium.from_base64(qrBase64));
      if (qrEntry.version === undefined || qrEntry.version !== 2) {
        throw new Error('Unknown version of QR code entry.');
      }
      if (qrEntry.data === undefined) {
        throw new Error('Invalid QR code entry.');
      }

      const masterPublicKey = new mcl.G2();
      masterPublicKey.deserialize(qrEntry.masterPublicKey);

      const info = QRCodeContent.encode(qrEntry.data).finish();
      return new Visit(scan(masterPublicKey,
          qrEntry.entryProof,
          info,
          entryTime,
            diary ? info : sodium.from_string('anonymous')));
    }

    /**
     * Uses the traces created by the healthAuthority to detect if
     * it has been exposed.
     *
     * @param traces sent by the health authority
     * @return true if at least one of the traces is positive
     */
    verifyExposure(traces: string[]): boolean {
      for (const trace of traces) {
        const trProto = Trace.decode(sodium.from_base64(trace));

        const secretKeyForIdentity = new mcl.G1();
        secretKeyForIdentity.deserialize(trProto.secretKeyForIdentity);

        const tr = {id: trProto.identity, skid: secretKeyForIdentity};

        const aux = match(this.data, tr);
        if (aux !== undefined) {
          const info = QRCodeContent.decode(aux);
          this.identity = `${info.name} - ${info.location} - ${info.room}`;
          return true;
        }
      }
      return false;
    }
}

/**
 * The room is now only one place where an organizer is
 * responsible.
 */
export class Room {
  constructor(public entry: QRCodeEntry) {
  }

  /**
   * Create a new room from an existing QRTrace code.
   * @param qrTrace
   * @return the room stored in the QRTrace
   */
  static fromQRTrace(qrTrace: string): Room {
    const qrTrace64 = qrTrace.replace(/^.*#/, '');
    const masterTraceRecordProto =
        QRCodeTrace.decode(sodium.from_base64(qrTrace64)).masterTraceRecord;
    const content = QRCodeContent.decode(masterTraceRecordProto.info);
    const entry = new QRCodeEntry({
      version: 2,
      data: content,
      masterPublicKey: masterTraceRecordProto.masterPublicKey,
      entryProof: new EntryProof({
        nonce1: masterTraceRecordProto.nonce1,
        nonce2: masterTraceRecordProto.nonce2,
      }),
    });
    return new Room(entry);
  }

  /**
   * Creates a room given the public information of an organizer.
   * @param org
   * @param venueType
   * @param name
   * @param location
   * @param room
   */
  static fromOrganizerPublic(
      org: IOrganizerPublic,
      venueType: number,
      name: string,
      location: string,
      room: string,
  ): Room {
    const entry = new QRCodeEntry({
      version: 2,
      data: new QRCodeContent({
        venueType, name, location, room,
        notificationKey: sodium.crypto_secretbox_keygen(),
      }),
      masterPublicKey: org.mpk.serialize(),
      entryProof: new EntryProof({
        nonce1: randomBytes(32),
        nonce2: randomBytes(32),
      }),
    });
    const now = new Date();
    entry.data.setValidFrom(now);
    now.setFullYear(now.getFullYear() + 1);
    entry.data.setValidFrom(now);
    return new Room(entry);
  }

  /**
   * Returns the QREntry for this room.
   * @param baseURL
   */
  getQRentry(baseURL: string): string {
    const qrcode = QRCodeEntry.encode(this.entry).finish();
    return `${baseURL}#` +
        `${sodium.to_base64(qrcode)}`;
  }

  /**
   * Returns the information about this room in binary format.
   */
  infoBinary(): Uint8Array {
    return QRCodeContent.encode(this.entry.data).finish();
  }


  /**
   * Returns the MasterTraceRecord for this room, given an organizer.
   * @param organizer
   */
  getMasterTraceRecord(organizer: Organizer): IMasterTrace {
    return {
      mpk: organizer.data.mpk,
      mskl: organizer.data.mskO,
      info: this.infoBinary(),
      nonce1: this.entry.entryProof.nonce1,
      nonce2: this.entry.entryProof.nonce2,
      ctxtha: organizer.data.ctxtha,
    };
  }
}
