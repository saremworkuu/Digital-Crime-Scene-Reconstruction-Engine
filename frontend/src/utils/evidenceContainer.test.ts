import test from 'node:test';
import assert from 'node:assert/strict';

import {
  formatEvidenceStatusLabel,
  getContainerExtractedCount,
  isEvidenceContainer,
} from './evidenceContainer.ts';

test('isEvidenceContainer identifies explicit containers, ZipArchive records, and legacy 0-event zips', () => {
  assert.equal(
    isEvidenceContainer({ filename: 'bundle.zip', parser_used: 'ZipArchive', event_count: 0, is_container: true }),
    true
  );
  assert.equal(
    isEvidenceContainer({ filename: 'legacy_archive.zip', parser_used: 'auto', event_count: 0 }),
    true
  );
  assert.equal(
    isEvidenceContainer({ filename: '01_apache_access.log', parser_used: 'web_server', event_count: 15, is_container: false }),
    false
  );
  assert.equal(
    isEvidenceContainer({ filename: '02_auth.log', parser_used: 'linux_auth', event_count: 0 }),
    false
  );
});

test('formatEvidenceStatusLabel renders extracted count for containers instead of Parsed with 0 events', () => {
  assert.equal(
    formatEvidenceStatusLabel({
      filename: 'case.zip',
      parser_used: 'ZipArchive',
      event_count: 0,
      status: 'Parsed',
      is_container: true,
      extracted_count: 10,
    }),
    'extracted: 10 files'
  );
  assert.equal(
    formatEvidenceStatusLabel({
      filename: 'single.zip',
      parser_used: 'ZipArchive',
      event_count: 0,
      status: 'Parsed',
      is_container: true,
      extracted_count: 1,
    }),
    'extracted: 1 file'
  );
  assert.equal(
    formatEvidenceStatusLabel({
      filename: 'auth.log',
      parser_used: 'linux_auth',
      event_count: 12,
      status: 'Parsed',
      is_container: false,
    }),
    'Parsed'
  );
  assert.equal(
    getContainerExtractedCount({
      extracted_count: null,
      extracted_results: [
        { filename: 'a.log', status: 'success' },
        { filename: 'b.log', status: 'duplicate' },
        { filename: 'bad.exe', status: 'failed' },
      ],
    }),
    2
  );
});
