import test from 'node:test';
import assert from 'node:assert/strict';

import { computeGraphExportBox } from './graphExport.ts';

test('computeGraphExportBox expands viewBox to cover negative top/side nodes without cropping', () => {
  const nodes = [
    { id: 'top-1', label: '192.0.2.56' },
    { id: 'center', label: 'WEB-01' },
    { id: 'bottom', label: 'www-data' },
  ];
  const positions = {
    'top-1': { x: 420, y: -90 },
    center: { x: 440, y: 180 },
    bottom: { x: 760, y: 510 },
  };

  const box = computeGraphExportBox(nodes, positions, null, { width: 880, height: 520 });
  assert.ok(box.minY <= -90 - 32 - 48, `Expected minY to include top node halo and padding, got ${box.minY}`);
  assert.ok(box.minY + box.height >= 510 + 56 + 48, `Expected bottom to include bottom label and padding`);
  assert.ok(box.minX + box.width >= 760 + 70 + 48, `Expected right bound to include rightmost node`);
});

test('computeGraphExportBox merges DOM getBBox when edges extend outside node centers', () => {
  const box = computeGraphExportBox(
    [{ id: 'a', label: 'A' }],
    { a: { x: 100, y: 100 } },
    { x: 20, y: -60, width: 500, height: 400 }
  );
  assert.ok(box.minX <= 20 - 48);
  assert.ok(box.minY <= -60 - 48);
  assert.ok(box.minX + box.width >= 520 + 48);
  assert.ok(box.minY + box.height >= 340 + 48);
});
