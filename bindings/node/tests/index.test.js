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

test('analyzeSourcesJson redacts source when includeSource is false', () => {
  const sources = [
    { name: 'ModSecret.bas', text: 'Public Sub SecretAction()\n    MsgBox "PrivatePassword"\nEnd Sub\n' }
  ];
  const full = vbaInsight.analyzeSourcesJson(sources, true);
  assert.ok(full.includes('PrivatePassword'));

  const redacted = vbaInsight.analyzeSourcesJson(sources, false);
  assert.ok(!redacted.includes('PrivatePassword'));
  const parsed = JSON.parse(redacted);
  assert.equal(parsed.modules.length, 1);
});

test('inspectMacroFileJson rejects invalid or empty container buffer', () => {
  assert.throws(() => {
    vbaInsight.inspectMacroFileJson(Buffer.from('not a zip or cfb'));
  }, /inspection failed/);

  assert.throws(() => {
    vbaInsight.inspectMacroFileJson(Buffer.alloc(0));
  }, /inspection failed/);
});

test('inspectMacroFileMarkdown and inspectMacroFileSarif reject invalid buffer', () => {
  assert.throws(() => {
    vbaInsight.inspectMacroFileMarkdown(Buffer.from('corrupt'));
  }, /inspection failed/);

  assert.throws(() => {
    vbaInsight.inspectMacroFileSarif(Buffer.from('corrupt'), 'test.xlsm');
  }, /inspection failed/);
});
