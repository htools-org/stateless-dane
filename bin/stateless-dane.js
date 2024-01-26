#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const Config = require('bcfg');
const { NodeClient } = require('hs-client');
const rsa = require('bcrypto/lib/rsa');
const { StatelessDANECertificate } = require('../lib');
const pkg = require('../package.json');

const nodePorts = {
  main: 12037,
  testnet: 13037,
  regtest: 14037,
  simnet: 15037
};

const HELP = `
stateless-dane v${pkg.version}

Usage:
    stateless-dane inspect-cert <filepath>
    stateless-dane generate <name> [--sign <true|false>] [--public-key-file <filepath>]
    stateless-dane get-ext-data <name> [--parsed <true|false>]


Options:
    --sign <bool>                   whether to sign the certificate (default: true)
    --parsed <bool>                 whether to return parsed extension data (default: true)
    --public-key-file <filepath>    create a certificate with this public key file, expects json (default: generated keypair)
                                    (example of public key format can be found at examples/sample-public-key.json)

    [all hsd client options like http-host, api-key, etc.]


Examples:
    * Inspect an existing certificate:
        $ stateless-dane inspect-cert /tmp/cert.pem

    * Generate a new certificate for letsdane:
        $ stateless-dane generate letsdane

    * Only get raw extension data to be used by other cert issuers:
        $ stateless-dane get-ext-data letsdane --parsed false
`;


// Main

(async () => {
  // HSD Node Client
  const config = new Config('hsd', {
    suffix: 'network',
    fallback: 'main',
    alias: {
      'n': 'network',
      'u': 'url',
      'uri': 'url',
      'k': 'api-key',
      's': 'ssl',
      'h': 'http-host',
      'p': 'http-port'
    }
  });
  config.load({
    argv: true,
    env: true,
  });
  config.open('hsd.conf');

  const network = config.str('network', 'main');
  const nodeClient = new NodeClient({
    url: config.str('url'),
    apiKey: config.str('api-key'),
    ssl: config.bool('ssl'),
    host: config.str('http-host'),
    port: config.uint('http-port')
      || nodePorts[network]
      || nodePorts.main,
    timeout: config.uint('timeout'),
    limit: config.uint('limit')
  });

  const command = config.str(0);

  const sign = config.bool('sign', true);
  const publicKeyFile = config.str('public-key-file');
  var publicKeyJson
  if (publicKeyFile) {
    publicKeyJson = JSON.parse(fs.readFileSync(publicKeyFile, 'utf8'));
  }
  const parsed = config.bool('parsed', true);

  switch (command) {
    case 'inspect-cert':
      {
        const filepath = config.str(1);
        if (!filepath) {
          console.log(HELP);
          return;
        }
        const cert = StatelessDANECertificate.fromPath(nodeClient, filepath);
        console.log(JSON.stringify(cert.format(), null, 4));
      }
      break;

    case 'generate':
      {
        const name = config.str([1, 'name']);
        if (!name) {
          console.log(HELP);
          return;
        }
        const cert = new StatelessDANECertificate(nodeClient, name);
        if (publicKeyJson) {
          const parsed = {
            n: Buffer.from(publicKeyJson.n, 'hex'),
            e: Buffer.from(publicKeyJson.e, 'hex'),
          };
          cert.publicKey = rsa.publicKeyImport(parsed);
        }
        await cert.create();
        if (sign) {
          cert.sign();
        }
        console.log(cert.cert.toPEM());
      }
      break;

    case 'get-ext-data':
      {
        const name = config.str([1, 'name']);
        if (!name) {
          console.log(HELP);
          return;
        }
        const cert = new StatelessDANECertificate(nodeClient, name);
        const extensions = await Promise.all([
          cert._getUrkelProofExtension(),
          cert._getDnssecChainExtension(),
        ]);
        console.log(JSON.stringify(extensions.map(ext => ext.getJSON(parsed))));
      }
      break;

    default:
      console.log(HELP);
      return;
  }
})().catch(console.error);
