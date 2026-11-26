export const MAX_FOLDER_FILES = 100;
export const MAX_FOLDER_FILE_SIZE = 100 * 1024 * 1024; // 100 MB per file
export const MAX_FOLDER_TOTAL_SIZE = 250 * 1024 * 1024; // 250 MB per batch

const JUNK_FILENAMES = new Set(['.ds_store', 'thumbs.db', 'desktop.ini']);

export interface FolderLimits {
  maxFiles?: number;
  maxFileSize?: number;
  maxTotalSize?: number;
}

export interface CollectedUploadFile {
  file: File;
  relativePath: string;
}

export interface FolderWalkResult {
  files: CollectedUploadFile[];
  skippedJunkCount: number;
  skippedDirectoryCount: number;
}

export interface BatchValidationResult {
  validFiles: CollectedUploadFile[];
  oversizedFiles: { file: File; relativePath: string; reason: string }[];
  batchError: string | null;
}

export interface FileSystemEntryLike {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  fullPath?: string;
}

export interface FileSystemFileEntryLike extends FileSystemEntryLike {
  file: (successCallback: (file: File) => void, errorCallback?: (err: unknown) => void) => void;
}

export interface FileSystemDirectoryReaderLike {
  readEntries: (
    successCallback: (entries: FileSystemEntryLike[]) => void,
    errorCallback?: (err: unknown) => void,
  ) => void;
}

export interface FileSystemDirectoryEntryLike extends FileSystemEntryLike {
  createReader: () => FileSystemDirectoryReaderLike;
}

export interface DataTransferItemLike {
  kind: string;
  webkitGetAsEntry?: () => FileSystemEntryLike | null;
  getAsFile?: () => File | null;
}

export interface DataTransferLike {
  items?: ArrayLike<DataTransferItemLike> | null;
  files?: ArrayLike<File> | null;
}

export function normalizeRelativePath(rawPath: string): string {
  return String(rawPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .split('/')
    .filter(Boolean)
    .join('/');
}

/**
 * Return true for directories/junk/hidden entries that must not be uploaded as evidence
 * (__MACOSX, .DS_Store, Thumbs.db, desktop.ini, AppleDouble ._*, and hidden dot-segments like .git).
 */
export function isSkippedPath(rawPath: string): boolean {
  const normalized = normalizeRelativePath(rawPath);
  if (!normalized) return true;

  const segments = normalized.split('/');
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    const lower = seg.toLowerCase();
    if (lower === '__macosx') return true;
    if (seg.startsWith('.')) return true;
    if (i === segments.length - 1 && JUNK_FILENAMES.has(lower)) return true;
  }
  return false;
}

function sortCollectedFiles(files: CollectedUploadFile[]): CollectedUploadFile[] {
  return [...files].sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}

function formatMiB(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Normalize a FileList (from <input type="file"> or <input webkitdirectory>) into
 * deterministic, junk-filtered upload items.
 */
export function collectFilesFromFileList(fileList: ArrayLike<File> | null | undefined): FolderWalkResult {
  if (!fileList || fileList.length === 0) {
    return { files: [], skippedJunkCount: 0, skippedDirectoryCount: 0 };
  }

  const collected: CollectedUploadFile[] = [];
  let skippedJunkCount = 0;

  for (let i = 0; i < fileList.length; i += 1) {
    const file = fileList[i];
    if (!file) continue;
    const rawRelative = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    const relativePath = normalizeRelativePath(rawRelative) || file.name;

    if (isSkippedPath(relativePath)) {
      skippedJunkCount += 1;
      continue;
    }

    collected.push({ file, relativePath });
  }

  return {
    files: sortCollectedFiles(collected),
    skippedJunkCount,
    skippedDirectoryCount: 0,
  };
}

function readAllDirectoryEntries(reader: FileSystemDirectoryReaderLike): Promise<FileSystemEntryLike[]> {
  return new Promise((resolve, reject) => {
    const allEntries: FileSystemEntryLike[] = [];

    const readNextBatch = () => {
      reader.readEntries(
        (batch) => {
          if (!batch || batch.length === 0) {
            resolve(allEntries);
            return;
          }
          allEntries.push(...batch);
          readNextBatch();
        },
        (err) => reject(err),
      );
    };

    readNextBatch();
  });
}

function getFileFromEntry(entry: FileSystemFileEntryLike): Promise<File> {
  return new Promise((resolve, reject) => {
    entry.file(
      (file) => resolve(file),
      (err) => reject(err),
    );
  });
}

async function walkEntry(
  entry: FileSystemEntryLike,
  parentPath: string,
  state: { files: CollectedUploadFile[]; skippedJunkCount: number; skippedDirectoryCount: number },
): Promise<void> {
  const entryPath = normalizeRelativePath(parentPath ? `${parentPath}/${entry.name}` : entry.name || entry.fullPath || '');

  if (isSkippedPath(entryPath)) {
    state.skippedJunkCount += 1;
    return;
  }

  if (entry.isDirectory) {
    state.skippedDirectoryCount += 1;
    const dirEntry = entry as FileSystemDirectoryEntryLike;
    if (typeof dirEntry.createReader !== 'function') return;
    const childEntries = await readAllDirectoryEntries(dirEntry.createReader());
    for (const child of childEntries) {
      await walkEntry(child, entryPath, state);
    }
    return;
  }

  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntryLike;
    if (typeof fileEntry.file !== 'function') return;
    const file = await getFileFromEntry(fileEntry);
    state.files.push({
      file,
      relativePath: entryPath || file.name,
    });
  }
}

/**
 * Snapshot DataTransfer synchronously and recursively walk any dropped files/folders
 * via webkitGetAsEntry(), falling back to DataTransfer.files when entry APIs are absent.
 */
export async function collectFilesFromDataTransfer(dataTransfer: DataTransferLike | null | undefined): Promise<FolderWalkResult> {
  if (!dataTransfer) {
    return { files: [], skippedJunkCount: 0, skippedDirectoryCount: 0 };
  }

  // Must capture entries synchronously before any await because browsers clear DataTransferItemList on yield.
  const entries: FileSystemEntryLike[] = [];
  const fallbackFiles: File[] = [];
  const items = dataTransfer.items;

  if (items && items.length > 0) {
    for (let i = 0; i < items.length; i += 1) {
      const item = items[i];
      if (!item || item.kind !== 'file') continue;
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) {
        entries.push(entry);
      } else if (typeof item.getAsFile === 'function') {
        const f = item.getAsFile();
        if (f) fallbackFiles.push(f);
      }
    }
  }

  if (entries.length === 0) {
    if (fallbackFiles.length > 0) {
      return collectFilesFromFileList(fallbackFiles);
    }
    return collectFilesFromFileList(dataTransfer.files);
  }

  const state = {
    files: [] as CollectedUploadFile[],
    skippedJunkCount: 0,
    skippedDirectoryCount: 0,
  };

  for (const entry of entries) {
    await walkEntry(entry, '', state);
  }

  for (const f of fallbackFiles) {
    const rel = normalizeRelativePath((f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name) || f.name;
    if (isSkippedPath(rel)) {
      state.skippedJunkCount += 1;
    } else {
      state.files.push({ file: f, relativePath: rel });
    }
  }

  return {
    files: sortCollectedFiles(state.files),
    skippedJunkCount: state.skippedJunkCount,
    skippedDirectoryCount: state.skippedDirectoryCount,
  };
}

/**
 * Enforce batch file count, per-file size limit, and total folder size limit.
 */
export function validateUploadBatch(
  entries: CollectedUploadFile[],
  limits: FolderLimits = {},
): BatchValidationResult {
  const maxFiles = limits.maxFiles ?? MAX_FOLDER_FILES;
  const maxFileSize = limits.maxFileSize ?? MAX_FOLDER_FILE_SIZE;
  const maxTotalSize = limits.maxTotalSize ?? MAX_FOLDER_TOTAL_SIZE;

  if (entries.length > maxFiles) {
    return {
      validFiles: [],
      oversizedFiles: [],
      batchError: `Folder contains ${entries.length} files, exceeding the maximum of ${maxFiles} files per batch.`,
    };
  }

  const validFiles: CollectedUploadFile[] = [];
  const oversizedFiles: { file: File; relativePath: string; reason: string }[] = [];
  let totalBytes = 0;

  for (const item of entries) {
    if (item.file.size > maxFileSize) {
      oversizedFiles.push({
        file: item.file,
        relativePath: item.relativePath,
        reason: `File exceeds maximum allowed size of ${formatMiB(maxFileSize)}.`,
      });
      continue;
    }
    totalBytes += item.file.size;
    validFiles.push(item);
  }

  if (totalBytes > maxTotalSize) {
    return {
      validFiles: [],
      oversizedFiles,
      batchError: `Folder total size (${formatMiB(totalBytes)}) exceeds the maximum allowed ${formatMiB(maxTotalSize)} per batch.`,
    };
  }

  return {
    validFiles,
    oversizedFiles,
    batchError: null,
  };
}
