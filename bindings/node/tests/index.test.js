const test = require('node:test');
const assert = require('node:assert/strict');
const vbaInsight = require('../index.js');

test('vba-insight version returns version string', () => {
  const ver = vbaInsight.version();
  assert.equal(typeof ver, 'string');
  assert.ok(ver.length > 0);
});

test('analyzeSourcesJson performs static analysis', () => {
  const sources = [
    { name: 'Mod1.bas', text: 'Public Sub Test()\n    MsgBox "Node.js Test"\nEnd Sub\n' }
  ];
  const raw = vbaInsight.analyzeSourcesJson(sources, true);
  const parsed = JSON.parse(raw);
  assert.ok(parsed.modules);
  assert.equal(parsed.modules.length, 1);
  assert.equal(parsed.modules[0].name, 'Mod1');
});

test('inspectMacroFileJson rejects invalid container buffer', () => {
  assert.throws(() => {
    vbaInsight.inspectMacroFileJson(Buffer.from('not a zip or cfb'));
  }, /inspection failed/);
});
