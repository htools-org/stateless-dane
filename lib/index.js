const fs = require('node:fs');
const assert = require('bsert');
const rsa = require('bcrypto/lib/rsa');
const x509 = require('bcrypto/lib/encoding/x509');
const SHA256 = require('bcrypto/lib/sha256');
const { asn1 } = require('bcrypto/lib/encoding');
const NodeClient = require('hs-client/lib/node');

const { N_ROOTS_OLD } = require('./common');
const certificate = require('./certificate');
const utils = require('./utils');
const { UrkelProofExtension, DnssecChainExtension } = require('./extensions');


class StatelessDANECertificate {
  /**
   * @param {string} name FQDN
   * @param {NodeClient} nodeClient
   * @param {object} options
   * @param {number} options.port
   * @param {string} options.resolverIP
   * @param {number} options.resolverPort
   */
  constructor(nodeClient, name, options = {}) {
    // assert.enforce(nodeClient instanceof NodeClient, 'nodeClient', 'NodeClient');
    assert.enforce(nodeClient.socket, 'nodeClient', 'NodeClient');
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

    this.options = {
      port: 443,
      resolverIP: '127.0.0.1',
      resolverPort: 5350,
      ...options,
    };
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
    const oldRoot = await utils.getOldRoot(this.nodeClient, N_ROOTS_OLD);
    const oldProof = await utils.getNameProofAtRoot(this.nodeClient, tld, oldRoot);

    const rootProofs = [];

    // find last update
    const lastUpdate = await utils.getLastUrkelUpdate(this.nodeClient, tld);

    if (lastUpdate.isUpdatedInOldTree) {
      // if very old, one proof is enough
      rootProofs.push([oldRoot, oldProof]);
    } else if (lastUpdate.isUpdatedInTree) {
      // if committed in tree, but not very old,
      // include both proofs (old and the root that includes the UPDATE)
      rootProofs.push([oldRoot, oldProof]);

      const newRoot = lastUpdate.txUpdateInTreeRoot;
      const newProof = await utils.getNameProofAtRoot(this.nodeClient, tld, newRoot);
      rootProofs.push([newRoot, newProof]);
    } else {
      // not committed to tree yet
      console.warn('name has not been committed to tree yet, only including old rootproof.');
      rootProofs.push([oldRoot, oldProof]);
    }

    assert(rootProofs.length); // sanity check
    const ext = UrkelProofExtension.create(rootProofs);
    return ext;
  }

  async _getDnssecChainExtension() {
    const chain = await utils.getDnssecChain(this.name, {
      port: this.options.port,
      resolverIP: this.options.resolverIP,
      resolverPort: this.options.resolverPort,
    });
    assert(chain, 'No DNSSEC chain');

    const ext = DnssecChainExtension.create(chain, this.options.port);
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
   * @param {object} options
   * @param {number} options.port
   * @param {string} options.resolverIP
   * @param {number} options.resolverPort
   * @returns {StatelessDANECertificate}
   */
  static fromPath(nodeClient, filepath, options) {
    const pemCert = fs.readFileSync(filepath).toString().trim();

    /** @type {x509.Certificate} */
    const cert = x509.Certificate.fromPEM(pemCert);
    const name = utils.getCNFromCert(cert);

    const daneCert = new this(nodeClient, name, options);
    daneCert.cert = cert;
    daneCert.replaceExtensions();
    return daneCert;
  }
}

module.exports = { StatelessDANECertificate };
