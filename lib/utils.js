const { promisify } = require('node:util');
const exec = promisify(require('node:child_process').exec);
const assert = require('bsert');
const blake2b = require('bcrypto/lib/blake2b');
const x509 = require('bcrypto/lib/encoding/x509');
const asn1 = require('bcrypto/lib/encoding/asn1');
const Proof = require('urkel/lib/proof');
const { Record } = require('bns/lib/wire');
const { parseDelvOutput } = require('./delv-parser');
const NodeClient = require('hs-client/lib/node');


/**
 * @param {NodeClient} nodeClient
 * @param {number} n
 * @returns {Buffer} root hash
 */
async function getOldRoot(nodeClient, n) {
  // TODO: get -Nth root, using latest for now
  const info = await nodeClient.getInfo();
  return Buffer.from(info.chain.treeRoot, 'hex');
}


/**
 * @param {NodeClient} nodeClient
 * @param {string} name
 * @param {Buffer} root
 * @returns {Proof}
 */
async function getNameProofAtRoot(nodeClient, name, root) {
  const res = await nodeClient.execute('getnameproof', [name, root && root.toString('hex')]);
  const proof = Proof.fromJSON(res.proof, blake2b, 256);
  return proof;
}

/**
 * @param {string} name
 * @returns {Promise<Record[]|null>}
 */
async function getDnssecChain(name) {
  // TODO: better fqdn test
  if (!/^[a-zA-Z0-9_\-.]+$/m.test(name)) {
    throw new Error('Invalid name.');
  }
  let output = await exec(`delv @127.0.0.1 -p 5350 -a ~/.hsd-ksk _443._tcp.${name} TLSA +rtrace +mtrace +nosplit`);

  if (!output.stdout.includes('; fully validated')) {
    return null;
  }

  const parsedOutput = parseDelvOutput(output.stderr);
  const records = parsedOutput.reduce((x, y) => x.concat(y.answer), []);
  return records;
}

/**
 * @param {x509.Certificate} cert
 * @param {string} oid
 * @returns {x509.Extension|null}
 */
function getExtensionFromCertByOID(cert, oid) {
  assert.enforce(cert instanceof x509.Certificate, 'cert', 'Certificate');
  assert.enforce(typeof oid === 'string', 'oid', 'string');

  /** @type {x509.Extension[]} */
  const extensions = cert.tbsCertificate.extensions.extensions;

  const ext = extensions.find(ext => ext.extnID.toString() === oid) || null;
  return ext;
}

/**
 * @param {x509.Certificate} cert
 * @returns {string} commonname
 */
function getCNFromCert(cert) {
  assert.enforce(cert instanceof x509.Certificate, 'cert', 'Certificate');

  const subject = cert.tbsCertificate.subject;

  /** @type {x509.Attribute[]} */
  const attributes = subject.names.flatMap(rdn => rdn.attributes);

  const attrCN = attributes.find(attr => attr.id.toString() === asn1.objects.attrs.COMMONNAME);

  /** @type {string} */
  const cn = attrCN.value.node.value;
  return cn;
}


module.exports = {
  getOldRoot,
  getNameProofAtRoot,
  getDnssecChain,
  getCNFromCert,
  getExtensionFromCertByOID,
};
