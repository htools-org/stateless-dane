const bio = require('bufio');
const x509 = require('bcrypto/lib/encoding/x509');
const asn1 = require('bcrypto/lib/encoding/asn1');
const blake2b = require('bcrypto/lib/blake2b');
const Proof = require('urkel/lib/proof');
const { Record } = require('bns/lib/wire');

// hsd is optional
/** @type {import('hsd/lib/covenants/namestate')|null} */
let NameState = null;
/** @type {import('hsd/lib/dns/resource')|null} */
let Resource = null;
try {
  NameState = require('hsd/lib/covenants/namestate');
  Resource = require('hsd/lib/dns/resource').Resource;
} catch (err) { }


// https://freeoid.pythonanywhere.com/
const OID_URKEL_PROOF = "1.3.6.1.4.1.54392.5.1620"
const OID_DNSSEC_CHAIN = "1.3.6.1.4.1.54392.5.1621"

asn1.objects.extensions['UrkelProof'] = OID_URKEL_PROOF;
asn1.objects.extensionsByVal[OID_URKEL_PROOF] = 'UrkelProof';

asn1.objects.extensions['DnssecChain'] = OID_DNSSEC_CHAIN;
asn1.objects.extensionsByVal[OID_DNSSEC_CHAIN] = 'DnssecChain';


class UrkelProofExtension extends x509.Extension {

  constructor() {
    super();
    this.extnID.fromString(OID_URKEL_PROOF);
    this.critical.set(false);

    /** @type {number|null} proof count */
    this.len = null;

    /** @type {[Buffer,Proof][]} */
    this.rootProofs = null; // [root, proof]
  }

  /**
   * @param {[Buffer,Proof][]} rootProofs array of [root,proof]
   */
  inject(rootProofs) {
    if (!Buffer.isBuffer(rootProofs?.[0][0])) {
      throw new Error('rootProofs must be an array of [root, proof].');
    }
    this.len = rootProofs.length;
    this.rootProofs = rootProofs.slice();

    const encodedRootProofs = this.rootProofs.map(
      ([root, proof]) => Buffer.concat([root, proof.encode(blake2b, 256)])
    );

    const value = Buffer.concat([Buffer.from([this.len]), ...encodedRootProofs]);

    this.extnValue.set(value);
  }

  /**
   * @param {[Buffer,Proof][]} rootProofs
   * @returns {UrkelProofExtension}
   */
  static create(rootProofs) {
    const ext = new this();
    ext.inject(rootProofs);
    return ext;
  }

  /**
   * @param {boolean} parsed whether to return parsed data
   */
  getJSON(parsed = true) {
    if (!parsed) {
      return {
        extnID: this.extnID.getJSON(),
        critical: this.critical.getJSON(),
        extnValue: this.extnValue.getJSON(),
      };
    }

    const proofs = this.rootProofs.map(([root, proof]) => {
      const json = proof.toJSON();
      json.root = root.toString('hex');
      // populate namestate and dns resource if hsd is available
      if (NameState && Resource) {
        json.ns = NameState.decode(proof.value);
        json.resource = Resource.decode(json.ns.data).getJSON();
      }
      return json;
    });

    return {
      extnID: this.extnID.getJSON(),
      critical: this.critical.getJSON(),
      extnValue: {
        proofs,
      },
    };
  }

  /**
   * @returns {number} size in bytes
   */
  getValueSize() {
    let size = 0;
    size += 1;  // len
    for (const [root, proof] of this.rootProofs) {
      size += 32; // root
      size += proof.getSize(blake2b, 256);
    }
    return size;
  }

  /**
   * @returns {Buffer}
   */
  encodeValue() {
    const size = this.getValueSize();
    const bw = bio.write(size);
    this.writeValue(bw);
    return bw.render();
  }

  /**
   * @param {import('bufio/lib/writer')} bw
   * @returns {import('bufio/lib/writer')}
   */
  writeValue(bw) {
    bw.writeU8(this.len);
    for (const [root, proof] of this.rootProofs) {
      bw.writeHash(root);
      proof.writeBW(bw, blake2b, 256);
    }
    return bw;
  }

  /**
   * @param {Buffer} data
   * @returns {UrkelProofExtension}
   */
  decodeValue(data) {
    const br = bio.read(data);
    return this.readValue(br);
  }

  /**
   * @param {import('bufio/lib/reader')} br
   * @returns {UrkelProofExtension}
   */
  readValue(br) {
    this.len = br.readU8();
    this.rootProofs = [];
    for (let i = 0; i < this.len; i++) {
      const root = br.readHash();
      const proof = Proof.readBR(br, blake2b, 256);
      this.rootProofs.push([root, proof]);
    }

    this.extnValue.set(this.encodeValue());
    return this;
  }

  /**
   * @param {asn1.OctString} extnValue
   * @returns {UrkelProofExtension}
   */
  static fromExtValue(extnValue) {
    const ext = new this().decodeValue(extnValue.value);
    return ext;
  }
}


// https://www.rfc-editor.org/rfc/rfc9102.html#name-dnssec-authentication-chain-
class DnssecChainExtension extends x509.Extension {

  constructor() {
    super();
    this.extnID.fromString(OID_DNSSEC_CHAIN);
    this.critical.set(false);

    /** @type {number|null} */
    this.port = null;
    /** @type {number|null} */
    this.lifetime = null;
    /** @type {Record[]} */
    this.chain = [];
  }

  /**
   * @param {Record[]} chain
   * @param {number} port
   * @param {number} lifetime
   */
  inject(chain, port = 443, lifetime = 0) {
    this.chain = chain.slice();
    this.port = port;
    this.lifetime = lifetime;

    const value = this.encodeValue();
    this.extnValue.set(value);
  }

  /**
   * @param {Record[]} chain
   * @param {number} port
   * @param {number} lifetime
   * @returns {DnssecChainExtension}
   */
  static create(chain, port = 443, lifetime = 0) {
    const ext = new this();
    ext.inject(chain, port, lifetime);
    return ext;
  }

  /**
   * @param {boolean} parsed whether to return parsed data
   */
  getJSON(parsed = true) {
    if (!parsed) {
      return {
        extnID: this.extnID.getJSON(),
        critical: this.critical.getJSON(),
        extnValue: this.extnValue.getJSON(),
      };
    }

    return {
      extnID: this.extnID.getJSON(),
      critical: this.critical.getJSON(),
      extnValue: {
        port: this.port,
        lifetime: this.lifetime,
        chain: this.chain.map(record => record.getJSON()),
      },
    };
  }

  /**
   * @returns {number} size in bytes
   */
  getValueSize() {
    let size = 0;
    size += 2; // port
    size += 2; // lifetime
    for (const record of this.chain) {
      size += record.getSize();
    }
    return size;
  }

  /**
   * @returns {Buffer}
   */
  encodeValue() {
    const size = this.getValueSize();
    const bw = bio.write(size);
    this.writeValue(bw);
    return bw.render();
  }

  /**
   * @param {import('bufio/lib/writer')} bw
   * @returns {import('bufio/lib/writer')}
   */
  writeValue(bw) {
    bw.writeU16BE(this.port);
    bw.writeU16BE(this.lifetime);
    for (const record of this.chain) {
      record.write(bw);
    }
    return bw;
  }

  /**
   * @param {Buffer} data
   * @returns {DnssecChainExtension}
   */
  decodeValue(data) {
    const br = bio.read(data);
    return this.readValue(br);
  }

  /**
   * @param {import('bufio/lib/reader')} br
   * @returns {DnssecChainExtension}
   */
  readValue(br) {
    this.port = br.readU16BE();
    this.lifetime = br.readU16BE();
    this.chain = [];

    while (br.left()) {
      this.chain.push(Record.read(br));
    }

    return this;
  }

  /**
   * @param {asn1.OctString} extnValue
   * @returns {DnssecChainExtension}
   */
  static fromExtValue(extnValue) {
    const ext = new this().decodeValue(extnValue.value);
    return ext;
  }
}


module.exports = {
  UrkelProofExtension,
  DnssecChainExtension,
}