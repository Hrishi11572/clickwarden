// Offline checks on a download's file name and MIME type.

export const EXECUTABLE_EXTS = new Set([
  'exe', 'msi', 'msix', 'appx', 'scr', 'bat', 'cmd', 'com', 'pif', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'hta', 'jar', 'lnk', 'dll', 'cpl', 'msc', 'reg', 'iso', 'img', 'vhd', 'vhdx', 'apk',
  'dmg', 'pkg', 'app', 'sh', 'run', 'bin', 'deb', 'rpm', 'appimage', 'xll', 'docm', 'xlsm', 'pptm',
  'one', 'chm', 'url', 'library-ms'
]);
const DOC_LIKE = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg', 'png',
  'gif', 'mp3', 'mp4', 'mov', 'avi', 'mkv', 'wav', 'zip', 'html', 'htm'
]);
const ARCHIVES = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'cab', 'ace', 'xz', 'bz2']);
const EXEC_MIMES = new Set([
  'application/x-msdownload', 'application/x-dosexec', 'application/x-msdos-program',
  'application/x-executable', 'application/vnd.microsoft.portable-executable', 'application/x-msi',
  'application/java-archive', 'application/x-sh', 'application/hta',
  'application/vnd.android.package-archive', 'application/x-ms-shortcut'
]);

export function baseName(path) {
  return (path || '').split(/[\\/]/).pop() || '';
}

/**
 * @returns {{score:number, reasons:string[], ext:string, risky:boolean}}
 */
export function analyzeFilename(path, mime = '') {
  const name = baseName(path);
  const reasons = [];
  let score = 0;
  const add = (pts, why) => { score += pts; reasons.push(why); };

  if (/[‪-‮⁦-⁩​-‏]/.test(name)) {
    add(50, 'File name contains hidden Unicode characters that disguise its real type');
  }
  const parts = name.toLowerCase().split('.');
  const ext = parts.length > 1 ? parts.pop().trim() : '';
  const prev = parts.length > 1 ? parts[parts.length - 1].trim() : '';
  const risky = EXECUTABLE_EXTS.has(ext);

  if (risky) add(30, `".${ext}" files can run code on your computer`);
  else if (ARCHIVES.has(ext)) add(5, 'Archive — what\'s inside is unknown until opened');
  if (risky && DOC_LIKE.has(prev)) add(40, `Double extension ".${prev}.${ext}" — pretends to be a ${prev.toUpperCase()} file`);
  if (/\s{3,}\.[a-z0-9]+$/i.test(name)) add(25, 'Lots of spaces before the extension to hide it');

  const m = (mime || '').toLowerCase().split(';')[0].trim();
  if (EXEC_MIMES.has(m) && !risky) add(35, `Named ".${ext || 'no extension'}" but the server says it is a program (${m})`);

  return { score, reasons, ext, risky };
}
