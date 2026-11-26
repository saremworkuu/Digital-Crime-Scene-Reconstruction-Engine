import test from 'node:test';
import assert from 'node:assert/strict';

import {
  collectFilesFromDataTransfer,
  collectFilesFromFileList,
  isSkippedPath,
  validateUploadBatch,
  type DataTransferLike,
  type FileSystemDirectoryEntryLike,
  type FileSystemEntryLike,
  type FileSystemFileEntryLike,
} from './folderUpload.ts';

function makeFile(name: string, content = 'sample', relativePath?: string): File {
  const file = new File([content], name, { type: 'text/plain' });
  if (relativePath) {
    Object.defineProperty(file, 'webkitRelativePath', {
      value: relativePath,
      configurable: true,
    });
  }
  return file;
}

function makeFileEntry(name: string, content = 'sample'): FileSystemFileEntryLike {
  const fileObj = makeFile(name, content);
  return {
    isFile: true,
    isDirectory: false,
    name,
    file: (cb) => cb(fileObj),
  };
}

function makeDirEntry(name: string, children: FileSystemEntryLike[], chunkSize = 100): FileSystemDirectoryEntryLike {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader: () => {
      let offset = 0;
      return {
        readEntries: (cb) => {
          const slice = children.slice(offset, offset + chunkSize);
          offset += slice.length;
          cb(slice);
        },
      };
    },
  };
}

test('isSkippedPath filters junk and hidden paths while keeping nested evidence and zips', () => {
  assert.equal(isSkippedPath('__MACOSX/._auth.log'), true);
  assert.equal(isSkippedPath('evidence/.DS_Store'), true);
  assert.equal(isSkippedPath('evidence/sub/Thumbs.db'), true);
  assert.equal(isSkippedPath('evidence/sub/desktop.ini'), true);
  assert.equal(isSkippedPath('evidence/.git/HEAD'), true);
  assert.equal(isSkippedPath('evidence/.git/objects/ab/cd'), true);
  assert.equal(isSkippedPath('evidence/._hidden_copy.log'), true);

  assert.equal(isSkippedPath('evidence/sub/access.log'), false);
  assert.equal(isSkippedPath('evidence/nested/bundle.zip'), false);
  assert.equal(isSkippedPath('syslog'), false);
});

test('collectFilesFromDataTransfer recursively walks subfolders, handles paginated readEntries, skips junk, and sorts deterministically', async () => {
  const rootDir = makeDirEntry(
    'case_folder',
    [
      makeFileEntry('.DS_Store', 'junk'),
      makeFileEntry('Thumbs.db', 'junk'),
      makeDirEntry('__MACOSX', [makeFileEntry('._web.log', 'appledouble')]),
      makeDirEntry('.git', [makeFileEntry('config', 'gitcfg'), makeFileEntry('HEAD', 'ref')]),
      makeFileEntry('z_last.log', 'late log'),
      makeDirEntry('sub_a', [
        makeFileEntry('nested.zip', 'zipbytes'),
        makeFileEntry('a_first.csv', 'ts,host\n'),
      ]),
    ],
    2 // Force multiple readEntries() calls like Chromium pagination
  );

  const dataTransfer: DataTransferLike = {
    items: [
      {
        kind: 'file',
        webkitGetAsEntry: () => rootDir,
      },
    ],
  };

  const res = await collectFilesFromDataTransfer(dataTransfer);
  assert.deepEqual(
    res.files.map((item) => item.relativePath),
    [
      'case_folder/sub_a/a_first.csv',
      'case_folder/sub_a/nested.zip',
      'case_folder/z_last.log',
    ]
  );
  // Each file preserves its leaf basename for existing single-file upload parity
  assert.deepEqual(
    res.files.map((item) => item.file.name),
    ['a_first.csv', 'nested.zip', 'z_last.log']
  );
  assert.equal(res.skippedJunkCount, 4);
  assert.equal(res.skippedDirectoryCount, 2);
});

test('collectFilesFromFileList normalizes webkitdirectory selections identically to dropped trees', () => {
  const f1 = makeFile('z.log', 'z', 'folder/z.log');
  const f2 = makeFile('a.log', 'a', 'folder/nested/a.log');
  const junk = makeFile('.DS_Store', 'j', 'folder/.DS_Store');
  const hiddenGit = makeFile('HEAD', 'h', 'folder/.git/HEAD');

  const res = collectFilesFromFileList([f1, junk, f2, hiddenGit]);
  assert.deepEqual(
    res.files.map((item) => item.relativePath),
    ['folder/nested/a.log', 'folder/z.log']
  );
  assert.equal(res.skippedJunkCount, 2);
});

test('validateUploadBatch enforces file count, per-file size, and total batch size limits', () => {
  const small1 = { file: makeFile('a.log', '12345'), relativePath: 'dir/a.log' };
  const small2 = { file: makeFile('b.log', '123456'), relativePath: 'dir/b.log' };
  const big = { file: makeFile('big.log', '01234567890'), relativePath: 'dir/big.log' };

  // Max file count limit
  const countLimited = validateUploadBatch([small1, small2], { maxFiles: 1, maxFileSize: 100, maxTotalSize: 100 });
  assert.match(countLimited.batchError || '', /exceeding the maximum of 1 files/);

  // Per-file size limit rejects oversized file cleanly without blocking smaller valid ones
  const fileLimited = validateUploadBatch([small1, big], { maxFiles: 10, maxFileSize: 8, maxTotalSize: 100 });
  assert.equal(fileLimited.batchError, null);
  assert.equal(fileLimited.validFiles.length, 1);
  assert.equal(fileLimited.oversizedFiles.length, 1);
  assert.equal(fileLimited.oversizedFiles[0].file.name, 'big.log');

  // Total batch size limit
  const totalLimited = validateUploadBatch([small1, small2], { maxFiles: 10, maxFileSize: 100, maxTotalSize: 10 });
  assert.match(totalLimited.batchError || '', /exceeds the maximum allowed/);
});
