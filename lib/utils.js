const { promisify } = require('node:util');
const exec = promisify(require('node:child_process').exec);
const path = require('node:path');
const assert = require('bsert');
const blake2b = require('bcrypto/lib/blake2b');
const x509 = require('bcrypto/lib/encoding/x509');
const asn1 = require('bcrypto/lib/encoding/asn1');
const Proof = require('urkel/lib/proof');
const { Record } = require('bns/lib/wire');
const { parseDelvOutput } = require('./delv-parser');
const NodeClient = require('hs-client/lib/node');

const { TREE_INTERVAL, N_ROOTS_OLD } = require('./common');

/**
 * @param {NodeClient} nodeClient
 * @param {number} n Nth last tree root (0 = latest, 1=prev, ...)
 * @returns {Promis<Buffer>} root hash
 */
async function getOldRoot(nodeClient, n) {
  assert(Number.isSafeInteger(n) && n >= 0 && n >>> 0 === n);

  const info = await nodeClient.getInfo();
  const { height, progress } = info.chain;

  if (progress < 0.999) {
    console.warn(`hsd node is not completely synced, urkel proofs may be out of date. (progress=${progress})`);
  }

  if (n === 0) {
    // latest
    return Buffer.from(info.chain.treeRoot, 'hex');
  }

  const blocksToRewind = n * TREE_INTERVAL;
  const oldBlockHeight = height - blocksToRewind;

  if (oldBlockHeight < 0) {
    throw new Error('Tree root requested is older than chain.');
  }

  // [blockheight, verbose (not-hex), details (txdetails)]
  const block = await nodeClient.execute('getblockbyheight', [oldBlockHeight, true, false]);
  return Buffer.from(block.treeroot, 'hex');
}


/**
 * @param {NodeClient} nodeClient
 * @param {string} name
 * @param {Buffer} root
 * @returns {Promise<Proof>}
 */
async function getNameProofAtRoot(nodeClient, name, root) {
  const res = await nodeClient.execute('getnameproof', [name, root ? root.toString('hex') : undefined]);
  const proof = Proof.fromJSON(res.proof, blake2b, 256);
  return proof;
}

/**
 * @param {NodeClient} nodeClient
 * @param {string} tld
 * @returns {Promise<object>}
 */
async function getLastUrkelUpdate(nodeClient, tld) {
  const chainHeight = (await nodeClient.getInfo()).chain.height;

  const latestNameInfo = await nodeClient.execute('getnameinfo', [tld]);

  let coin = latestNameInfo.info.owner;

  while (coin) {
    const tx = await nodeClient.getTX(coin.hash);
    if (!tx) break;
    const action = tx.outputs[coin.index].covenant.action;

    if (['REVEAL'].includes(action)) {
      // no namestate
      break;
    }
    if (!['UPDATE', 'REGISTER'].includes(action)) {
      coin = tx.inputs[coin.index].prevout;
      continue;
    }

    const blocksToTreeUpdateAfterTx = TREE_INTERVAL - (tx.height % TREE_INTERVAL);

    // height at which tx will be/is included in tree
    const txUpdateInTreeHeight = tx.height + blocksToTreeUpdateAfterTx + 1;
    const txUpdateInTreeRoot = (txUpdateInTreeHeight <= chainHeight) ?
      Buffer.from((await nodeClient.getBlockHeader(txUpdateInTreeHeight)).treeRoot, 'hex')
      : null;

    const latestTreeUpdateHeight = chainHeight - (chainHeight % TREE_INTERVAL) + 1;

    const isUpdatedInTree = txUpdateInTreeHeight <= latestTreeUpdateHeight;

    const isUpdatedInOldTree = txUpdateInTreeHeight <= (latestTreeUpdateHeight - N_ROOTS_OLD * TREE_INTERVAL);

    return {
      chainHeight,
      latestTreeUpdateHeight,
      txHeight: tx.height,
      txUpdateInTreeHeight,
      txUpdateInTreeRoot,
      isUpdatedInTree,
      isUpdatedInOldTree
    };
  }

  throw new Error('Name is not registered.');
}

/**
 * @param {string} name
 * @returns {Promise<Record[]|null>}
 */
async function getDnssecChain(name, { port = 443, resolverIP = '127.0.0.1', resolverPort = 5350 }) {
  // TODO: better fqdn test
  if (!/^[a-zA-Z0-9_\-.]+$/m.test(name)) {
    throw new Error('Invalid name.');
  }
  if (port <= 0 || 65535 < port) {
    throw new Error('Invalid port.');
  }
  const kskPath = path.resolve(__dirname, '../etc/hsd-ksk');
  let output = await exec(`delv @${resolverIP} -p ${resolverPort} -a ${kskPath} _${port}._tcp.${name} TLSA +rtrace +mtrace +nosplit`);

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
  getLastUrkelUpdate,
  getDnssecChain,
  getCNFromCert,
  getExtensionFromCertByOID,
};
