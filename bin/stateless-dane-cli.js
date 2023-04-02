#!/usr/bin/env node
'use strict';

const Config = require('bcfg/lib/config');
const { NodeClient } = require('hs-client');
const { StatelessDANECertificate } = require('..');
const pkg = require('../package.json');

const nodePorts = {
  main: 12037,
  testnet: 13037,
  regtest: 14037,
  simnet: 15037
};

const HELP = `
stateless-dane-cli v${pkg.version}

Usage:
    stateless-dane-cli inspect-cert <filepath>
    stateless-dane-cli generate <name> [--sign <true|false>] [--public-key <hex>]
    stateless-dane-cli get-ext-data <name> [--parsed <true|false>]


Options:
    --sign <bool>         whether to sign the certificate (default: true)
    --public-key <hex>    create a certificate with this public key (default: generated keypair)
    --parsed <bool>       whether to return parsed extension data (default: true)

    [all hsd client options like http-host, api-key, etc.]


Examples:
    * Inspect an existing certificate:
        $ stateless-dane-cli inspect-cert /tmp/cert.pem

    * Generate a new certificate for letsdane:
        $ stateless-dane-cli generate letsdane

    * Only get raw extension data to be used by other cert issuers:
        $ stateless-dane-cli get-ext-data letsdane --parsed false
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
  const publicKey = config.buf('public-key');
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
        if (publicKey) {
          cert.publicKey = publicKey;
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
