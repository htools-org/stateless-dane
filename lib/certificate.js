const x509 = require('bcrypto/lib/encoding/x509');
const rsa = require('bcrypto/lib/rsa');


async function createBaseCertificate({ name, publicKey }) {
  // https://github.com/pinheadmz/handout/blob/master/scripts/hnssec-gen.js

  const pubJSON = rsa.publicKeyExport(publicKey);

  // Timestamps and serial number
  // Use *yesterday* for start time to avoid UTC/timezone conflict
  const date = new Date();
  const month = date.getMonth() + 1;
  const day = date.getDate();
  if (day > 1) {
    date.setDate(day - 1);
  } else {
    date.setMonth((month + 11) % 12);
    date.setDate(30);
  }

  const serial =
    String(date.getFullYear()) +
    ('0' + String(month)).slice(-2) +
    ('0' + String(day)).slice(-2) +
    '00';
  const notBefore = date.toISOString().split('.')[0] + 'Z';
  date.setMonth(date.getMonth() + 3);
  const notAfter = date.toISOString().split('.')[0] + 'Z';

  // // hex-encode IP address
  // let ipaddr = '';
  // const bytes = host.split('.');
  // for (const byte of bytes)
  //   ipaddr += Buffer.from([parseInt(byte)]).toString('hex');

  // Basic details, leave out optional and more complex stuff
  const tbsJSON = {
    version: 2,
    serialNumber: serial,
    signature: {
      algorithm: 'RSASHA256',
      parameters: {
        type: 'NULL',
        node: null
      },
    },
    issuer: [],
    validity: {
      notBefore: { type: 'UTCTime', node: notBefore },
      notAfter: { type: 'UTCTime', node: notAfter },
    },
    subject: [],
    subjectPublicKeyInfo: {
      algorithm: {
        algorithm: 'RSAPublicKey',
        parameters: {
          type: 'NULL',
          node: null
        },
      },
      publicKey: {
        modulus: pubJSON.n,
        publicExponent: pubJSON.e
      }
    },
    extensions: [
      {
        extnID: 'SubjectAltName',
        critical: false,
        extnValue: [
          { type: 'DNSName', node: name },
          { type: 'DNSName', node: `*.${name}` },
          // { type: 'IPAddress', node: ipaddr }
        ]
      },
      {
        extnID: 'BasicConstraints',
        critical: false,
        extnValue: { cA: false, pathLenConstraint: 0 }
      },
      {
        extnID: 'KeyUsage',
        critical: false,
        extnValue: [
          'digitalSignature',
          'nonRepudiation',
          'keyEncipherment',
          'dataEncipherment'
        ]
      }
    ]
  };

  // Create to-be-signed certificate object
  const tbs = x509.TBSCertificate.fromJSON(tbsJSON);

  // Use helper functions for the complicated details
  tbs.issuer = x509.Entity.fromJSON({
    COMMONNAME: name
  });
  tbs.subject = x509.Entity.fromJSON({
    COMMONNAME: name
  });

  const cert = new x509.Certificate();
  cert.tbsCertificate = tbs;

  // no signautre added here

  return cert;
}

module.exports = { createBaseCertificate };
