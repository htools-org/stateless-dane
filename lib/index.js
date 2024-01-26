const fs = require('node:fs');
const assert = require('bsert');
const rsa = require('bcrypto/lib/rsa');
const x509 = require('bcrypto/lib/encoding/x509');
const SHA256 = require('bcrypto/lib/sha256');
const NodeClient = require('hs-client/lib/node');

const certificate = require('./certificate');
const utils = require('./utils');
const { UrkelProofExtension, DnssecChainExtension } = require('./extensions');
const { asn1 } = require('bcrypto/lib/encoding');


class StatelessDANECertificate {
  /**
   * @param {string} name FQDN
   * @param {NodeClient} nodeClient
   */
  constructor(nodeClient, name) {
    assert.enforce(nodeClient instanceof NodeClient, 'nodeClient', 'NodeClient');
    assert.enforce(typeof name === 'string', 'name', 'string');

    // TODO: handle FQDNs better
    if (name.endsWith('.')) name = name.slice(0, -1);

    /** @type {NodeClient} */
    this.nodeClient = nodeClient;

    /** @type {string} */
    this.name = name;

    /** @type {Buffer|null} */
    this.privateKey = null;

    /** @type {Buffer|null} */
    this.publicKey = null;

    /** @type {x509.Certificate|null} */
    this.cert = null;
  }

  async create() {
    // Generate new key pair if public key is not provided
    if (!this.publicKey) {
      this._generateKeypair();
    }

    // Create a base certificate
    // (SNI, etc. but nothing DANE-related)
    this.cert = await certificate.createBaseCertificate({
      name: this.name,
      publicKey: this.publicKey,
    });

    // Add DANE extensions to certificate
    await this.addDANEExtensions();
  }

  _generateKeypair() {
    this.privateKey = rsa.privateKeyGenerate(2048);
    this.publicKey = rsa.publicKeyCreate(this.privateKey);
  }

  async addDANEExtensions() {
    assert(this.cert, 'Certificate not created yet.');

    const [nameProofExt, dnssecChainExt] = await Promise.all([
      this._getUrkelProofExtension(),
      this._getDnssecChainExtension(),
    ]);

    const extensions = this.cert.tbsCertificate.extensions;

    extensions.extensions.push(nameProofExt);
    extensions.extensions.push(dnssecChainExt);
  }

  async _getUrkelProofExtension() {
    const tld = this.name.split('.').pop();
    const root = await utils.getOldRoot(this.nodeClient, 32);
    const proof = await utils.getNameProofAtRoot(this.nodeClient, tld, root);

    const ext = UrkelProofExtension.create(root, [proof]);
    return ext;
  }

  async _getDnssecChainExtension() {
    const chain = await utils.getDnssecChain(this.name);
    assert(chain, 'No DNSSEC chain');

    const ext = DnssecChainExtension.create(chain);
    return ext;
  }

  sign() {
    assert(this.cert, 'Certificate not created yet.');
    assert(this.privateKey, 'Private key not set.');

    const tbs = this.cert.tbsCertificate;

    // Serialize
    const msg = SHA256.digest(tbs.encode());

    // Sign
    const sig = rsa.sign('SHA256', msg, this.privateKey);

    this.cert.signatureAlgorithm.fromJSON({
      algorithm: 'RSASHA256',
      parameters: {
        type: 'NULL',
        node: null,
      },
    });

    this.cert.signature.fromJSON({
      bits: sig.length * 8,
      value: sig.toString('hex'),
    });
  }

  format() {
    return this.cert.format();
  }

  /**
   * For the extensions we care about,
   * use specific Extension classes derived
   * from generic extensions
   */
  replaceExtensions() {
    assert(this.cert, 'Certificate not created yet.');

    /** @type {x509.Extension[]} */
    const extensions = this.cert.tbsCertificate.extensions.extensions;

    for (let i = 0; i < extensions.length; i++) {
      if (extensions[i].extnID.toString() === asn1.objects.extensions.UrkelProof) {
        extensions[i] = UrkelProofExtension.fromExtValue(extensions[i].extnValue);
        continue;
      }

      if (extensions[i].extnID.toString() === asn1.objects.extensions.DnssecChain) {
        extensions[i] = DnssecChainExtension.fromExtValue(extensions[i].extnValue);
        continue;
      }
    }
  }

  /**
   * @param {NodeClient} nodeClient
   * @param {string} filepath
   * @returns {StatelessDANECertificate}
   */
  static fromPath(nodeClient, filepath) {
    const pemCert = fs.readFileSync(filepath).toString().trim();

    /** @type {x509.Certificate} */
    const cert = x509.Certificate.fromPEM(pemCert);
    const name = utils.getCNFromCert(cert);

    const daneCert = new this(nodeClient, name);
    daneCert.cert = cert;
    daneCert.replaceExtensions();
    return daneCert;
  }
}

module.exports = { StatelessDANECertificate };
