# stateless-dane

A library/utility for Stateless DANE certificates ([HIP-0017](https://hsd-dev.org/HIPs/proposals/0017/)).

> **Warning**
> Not ready for production use. This project (and spec) is in early stages and subject to breaking changes.

## Installation / Usage

In any case, a connection to a hsd node is required. Connection settings are read just like `hs-client` from `hsd.conf`, env and args.

#### As a CLI

The CLI can generate new and inspect existing certificates:

```
❯ stateless-dane-cli

stateless-dane-cli v0.0.1

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
```

#### As a library

Add as dependency with `npm i stateless-dane` and use it like:

```js
// A hs-client node client
const nodeClient = new NodeClient({
  port: network.rpcPort,
});

const name = 'some.domain';

// Init a new certificate
const cert = new StatelessDANECertificate(nodeClient, name);

// Optionally, set keypair (else, will be generated)
cert.publicKey = Buffer...
cert.privateKey = Buffer...

// Create and sign the certificate
await cert.create();
cert.sign();

// Export as PEM
console.log(cert.cert.toPEM());
```

## Contributing

Contributions are always welcome! However, please create an issue before starting any work so there won't be any repeated/wasted effort.

## Credits

Thanks to:

- @buffrr for the [HIP-17 spec](https://hsd-dev.org/HIPs/proposals/0017/)
- @pinheadmz for [handout](https://github.com/pinheadmz/handout)
