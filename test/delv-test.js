const fs = require('node:fs/promises');
const assert = require('bsert');
const { parseDelvOutput } = require('../lib/delv-parser');

describe('Delv Parser', function () {
  it('should parse output with multiple queries', async () => {
    const out = (await fs.readFile('./test/data/delv-out-letsdane.txt')).toString();
    const parsed = parseDelvOutput(out);
    assert.ok(Array.isArray(parsed));
    assert.strictEqual(parsed.length, 4);
  });

  it('should parse authority section', async () => {
    const out = (await fs.readFile('./test/data/delv-out-home.htools.txt')).toString();
    const parsed = parseDelvOutput(out);
    assert.ok(Array.isArray(parsed));
    assert.strictEqual(parsed.length, 4);
    assert.strictEqual(parsed[0].answer.length, 2);
    assert.strictEqual(parsed[0].authority.length, 2);
  });
});
