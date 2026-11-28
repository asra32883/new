/*
 * Attachment helpers: remove personal metadata from images before they are encrypted, and decide what is safe to preview.
 *
 * Photos carry GPS position, camera serial numbers, timestamps and thumbnails. We remove them by rewriting the file
 * container (no canvas: Tor Browser blocks or randomises canvas pixel reads, which would corrupt pictures).
 * JPEG keeps the EXIF *orientation* only, so pictures taken sideways still display upright.
 * Only JPEG, PNG, GIF and WebP are cleaned; every other file type is sent exactly as it is, and the UI says so.
 */
(function (root) {
  'use strict';

  function concat(parts) {
    var n = 0, i; for (i = 0; i < parts.length; i++) { n += parts[i].length; }
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }
  function ascii(b, at, len) { var s = ''; for (var i = 0; i < len; i++) { s += String.fromCharCode(b[at + i]); } return s; }

  function sniff(b) {
    if (b.length > 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) { return 'image/jpeg'; }
    if (b.length > 8 && b[0] === 0x89 && ascii(b, 1, 3) === 'PNG') { return 'image/png'; }
    if (b.length > 6 && (ascii(b, 0, 6) === 'GIF87a' || ascii(b, 0, 6) === 'GIF89a')) { return 'image/gif'; }
    if (b.length > 12 && ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') { return 'image/webp'; }
    return null;
  }

  // ---- JPEG ----------------------------------------------------------------------------------------------
  function exifOrientation(seg) {           // seg = whole APP1 segment including marker and length
    if (ascii(seg, 4, 4) !== 'Exif') { return null; }
    var t = 10, le = ascii(seg, t, 2) === 'II';
    if (!le && ascii(seg, t, 2) !== 'MM') { return null; }
    function u16(o) { return le ? seg[o] | (seg[o + 1] << 8) : (seg[o] << 8) | seg[o + 1]; }
    function u32(o) { return le ? (seg[o] | (seg[o + 1] << 8) | (seg[o + 2] << 16) | (seg[o + 3] << 24)) >>> 0 : ((seg[o] << 24) | (seg[o + 1] << 16) | (seg[o + 2] << 8) | seg[o + 3]) >>> 0; }
    if (t + 8 > seg.length) { return null; }
    var ifd = t + u32(t + 4);
    if (ifd + 2 > seg.length) { return null; }
    var count = u16(ifd);
    for (var i = 0; i < count; i++) {
      var e = ifd + 2 + i * 12;
      if (e + 12 > seg.length) { return null; }
      if (u16(e) === 0x0112) { var v = u16(e + 8); return v >= 2 && v <= 8 ? v : null; }
    }
    return null;
  }
  function minimalExif(orientation) {       // an APP1 that holds nothing but the orientation
    return new Uint8Array([0xFF, 0xE1, 0x00, 0x22, 0x45, 0x78, 0x69, 0x66, 0, 0,
      0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 8,
      0x00, 0x01, 0x01, 0x12, 0x00, 0x03, 0, 0, 0, 1, 0x00, orientation, 0, 0, 0, 0, 0, 0]);
  }
  function stripJpeg(b) {
    var out = [b.subarray(0, 2)], i = 2, orientation = null;
    while (i + 1 < b.length) {
      if (b[i] !== 0xFF) { return null; }
      var m = b[i + 1];
      if (m === 0xFF) { i++; continue; }
      if (m === 0xD9) { out.push(b.subarray(i, i + 2)); i = b.length; break; }
      if (m === 0xDA) { out.push(b.subarray(i)); i = b.length; break; }              // entropy-coded data to the end
      if (m === 0x01 || (m >= 0xD0 && m <= 0xD7)) { out.push(b.subarray(i, i + 2)); i += 2; continue; }
      if (i + 3 >= b.length) { return null; }
      var len = (b[i + 2] << 8) | b[i + 3];
      if (len < 2 || i + 2 + len > b.length) { return null; }
      var seg = b.subarray(i, i + 2 + len), keep = true;
      if (m === 0xE1) { orientation = orientation || exifOrientation(seg); keep = false; }         // EXIF and XMP
      else if (m === 0xFE || m === 0xED || (m >= 0xE3 && m <= 0xEF && m !== 0xEE)) { keep = false; } // comments, Photoshop, etc.
      else if (m === 0xE2 && ascii(seg, 4, 11) !== 'ICC_PROFILE') { keep = false; }
      else if (m === 0xEE && ascii(seg, 4, 5) !== 'Adobe') { keep = false; }
      if (keep) { out.push(seg); }
      i += 2 + len;
    }
    if (orientation) { out.splice(1, 0, minimalExif(orientation)); }
    return concat(out);
  }

  // ---- PNG -----------------------------------------------------------------------------------------------
  var PNG_KEEP = { IHDR: 1, PLTE: 1, IDAT: 1, IEND: 1, tRNS: 1, gAMA: 1, cHRM: 1, sRGB: 1, iCCP: 1, sBIT: 1, bKGD: 1, hIST: 1, pHYs: 1, acTL: 1, fcTL: 1, fdAT: 1 };
  function stripPng(b) {
    var out = [b.subarray(0, 8)], i = 8;
    while (i + 12 <= b.length) {
      var len = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      if (i + 12 + len > b.length) { return null; }
      if (PNG_KEEP[ascii(b, i + 4, 4)]) { out.push(b.subarray(i, i + 12 + len)); }
      i += 12 + len;
    }
    return i === b.length ? concat(out) : null;
  }

  // ---- WebP ----------------------------------------------------------------------------------------------
  function stripWebp(b) {
    var out = [], i = 12;
    while (i + 8 <= b.length) {
      var tag = ascii(b, i, 4), size = (b[i + 4] | (b[i + 5] << 8) | (b[i + 6] << 16) | (b[i + 7] << 24)) >>> 0, total = 8 + size + (size & 1);
      if (i + total > b.length + (size & 1)) { return null; }
      var chunk = b.slice(i, Math.min(i + total, b.length));
      if (tag === 'EXIF' || tag === 'XMP ') { i += total; continue; }
      if (tag === 'VP8X') { chunk[8] &= ~0x0C; }                                    // clear the EXIF and XMP flags
      out.push(chunk); i += total;
    }
    var body = concat(out), res = new Uint8Array(12 + body.length);
    res.set(b.subarray(0, 12)); res.set(body, 12);
    var riff = res.length - 8;
    res[4] = riff & 255; res[5] = (riff >> 8) & 255; res[6] = (riff >> 16) & 255; res[7] = (riff >>> 24) & 255;
    return res;
  }

  // ---- GIF -----------------------------------------------------------------------------------------------
  function stripGif(b) {
    var i = 13, out = [];
    function skipSub(at) { while (at < b.length && b[at] !== 0) { at += b[at] + 1; } return at + 1; }
    var flags = b[10];
    if (flags & 0x80) { i += 3 * (1 << ((flags & 7) + 1)); }
    out.push(b.subarray(0, i));
    while (i < b.length) {
      var t = b[i];
      if (t === 0x3B) { out.push(b.subarray(i, i + 1)); i++; break; }
      if (t === 0x21) {
        var label = b[i + 1], end = skipSub(i + 2);
        var app = label === 0xFF ? ascii(b, i + 3, 11) : '';
        var keep = label === 0xF9 || label === 0x01 || (label === 0xFF && (app === 'NETSCAPE2.0' || app === 'ANIMEXTS1.0'));
        if (keep) { out.push(b.subarray(i, end)); }
        i = end; continue;
      }
      if (t === 0x2C) {
        var start = i, lf = b[i + 9]; i += 10;
        if (lf & 0x80) { i += 3 * (1 << ((lf & 7) + 1)); }
        i = skipSub(i + 1);
        out.push(b.subarray(start, i)); continue;
      }
      return null;
    }
    return i <= b.length ? concat(out) : null;
  }

  // Returns { bytes, mime (sniffed, never the declared type), cleaned }. Unparseable images are NOT sent as they are:
  // cleaned is false and ok is false so the UI can refuse or warn.
  function clean(bytes) {
    var mime = sniff(bytes);
    if (!mime) { return { bytes: bytes, mime: null, cleaned: false, ok: true }; }
    var out = mime === 'image/jpeg' ? stripJpeg(bytes) : mime === 'image/png' ? stripPng(bytes) : mime === 'image/webp' ? stripWebp(bytes) : stripGif(bytes);
    if (!out) { return { bytes: bytes, mime: mime, cleaned: false, ok: false }; }
    return { bytes: out, mime: mime, cleaned: true, ok: true };
  }

  // File names are shown to other people: remove paths, control characters and bidirectional overrides.
  function safeName(name) {
    var n = String(name || 'file').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩‎‏]/g, '').trim();
    if (n.length > 120) { var dot = n.lastIndexOf('.'); var ext = dot > 0 && n.length - dot <= 12 ? n.slice(dot) : ''; n = n.slice(0, 120 - ext.length) + ext; }
    return n || 'file';
  }

  var api = { clean: clean, sniff: sniff, safeName: safeName, PREVIEW: { 'image/jpeg': 1, 'image/png': 1, 'image/gif': 1, 'image/webp': 1 } };
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  root.TorFiles = api;
})(typeof globalThis !== 'undefined' ? globalThis : window);
