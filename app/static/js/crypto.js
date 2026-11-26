/*
 * Tor-Mail browser crypto. All encryption, decryption, signing and key generation happens here, in the
 * browser, using the vendored OpenPGP.js (static/vendor/openpgp.min.js). No custom cryptography: this file
 * only chooses parameters and checks results.
 *
 * Plaintext layout (JSON, then signed and encrypted as one OpenPGP message):
 *   { v: 1, from, to: [...], subject, body, client_ts }
 * so the server never sees subject, body, or the recipient list.
 */
(function (root) {
  'use strict';
  var pgp = root.openpgp;
  if (!pgp) { throw new Error('OpenPGP.js is not loaded'); }

  var MIN_PASSPHRASE = 14;
  var LIMITS = { subject: 998, body: 150000, recipients: 20 };

  function checkPassphrase(p) {
    if (typeof p !== 'string' || p.length < MIN_PASSPHRASE) {
      return { ok: false, reason: 'Use at least ' + MIN_PASSPHRASE + ' characters (a few random words work well).' };
    }
    if (new Set(p.split('')).size < 6) { return { ok: false, reason: 'That passphrase is too repetitive.' }; }
    return { ok: true, reason: '' };
  }

  // Passphrase protection for stored private keys. Argon2 S2K needs AEAD; fall back to iterated S2K if
  // the environment cannot run it. The choice is reported so the UI can tell the user the truth.
  function protectionConfig(strong) {
    return strong ? { aeadProtect: true, s2kType: pgp.enums.s2k.argon2 } : {};
  }

  async function generateKey(username, passphrase, opts) {
    opts = opts || {};
    var chk = checkPassphrase(passphrase);
    if (!chk.ok) { throw new Error(chk.reason); }
    var host = opts.host || (typeof location !== 'undefined' && location.hostname) || 'tormail.invalid';
    var strong = opts.strongKdf !== false;
    var out;
    try {
      out = await pgp.generateKey({
        type: 'curve25519', userIDs: [{ name: username, email: username + '@' + host }],
        passphrase: passphrase, format: 'armored', config: protectionConfig(strong),
      });
    } catch (e) {
      if (!strong) { throw e; }
      strong = false;   // Argon2/WASM unavailable here: fall back, and say so
      out = await pgp.generateKey({
        type: 'curve25519', userIDs: [{ name: username, email: username + '@' + host }],
        passphrase: passphrase, format: 'armored', config: protectionConfig(false),
      });
    }
    var pub = await readPublicKey(out.publicKey);
    return { publicKey: out.publicKey, privateKey: out.privateKey, fingerprint: fingerprintOf(pub), kdf: strong ? 'argon2id' : 'iterated-sha256' };
  }

  function fingerprintOf(key) { return key.getFingerprint().toUpperCase(); }

  function formatFingerprint(fpr) { return fpr.replace(/(.{4})/g, '$1 ').trim(); }

  // Parse and sanity-check a public key received from anywhere (including our own server).
  async function readPublicKey(armored) {
    var key = await pgp.readKey({ armoredKey: armored });
    if (key.isPrivate()) { throw new Error('Expected a public key but received a private key'); }
    await key.getEncryptionKey();   // throws if expired, revoked, or without an encryption subkey
    return key;
  }

  // True only if every secret key packet in the armored key is passphrase-encrypted.
  async function isPassphraseProtected(armoredPrivate) {
    var key = await pgp.readPrivateKey({ armoredKey: armoredPrivate });
    return key.getKeys().every(function (k) { return !k.keyPacket.isDecrypted(); });
  }

  async function privateFingerprint(armoredPrivate) {
    var key = await pgp.readPrivateKey({ armoredKey: armoredPrivate });
    return fingerprintOf(key);
  }

  // Unlock one or more stored private keys with the passphrase. Keys that do not open are skipped.
  async function unlock(armoredList, passphrase) {
    var opened = [];
    for (var i = 0; i < armoredList.length; i++) {
      try {
        var k = await pgp.readPrivateKey({ armoredKey: armoredList[i] });
        opened.push(await pgp.decryptKey({ privateKey: k, passphrase: passphrase }));
      } catch (e) { /* wrong passphrase for this key */ }
    }
    if (!opened.length) { throw new Error('Wrong passphrase'); }
    return opened;
  }

  function validatePayload(p) {
    var ok = p && p.v === 1 && typeof p.from === 'string' && Array.isArray(p.to) && p.to.every(function (x) { return typeof x === 'string'; }) &&
      typeof p.subject === 'string' && typeof p.body === 'string' && typeof p.client_ts === 'number';
    if (!ok) { throw new Error('Malformed message contents'); }
    return p;
  }

  async function encryptMessage(args) {
    // args: { signingKey (unlocked), senderPublic (armored), recipientPublics (armored[]), from, to[], subject, body }
    if (args.subject.length > LIMITS.subject || args.body.length > LIMITS.body || args.to.length > LIMITS.recipients) {
      throw new Error('Message is too long');
    }
    var keys = [], seen = {};
    var armoredKeys = args.recipientPublics.concat([args.senderPublic]);
    for (var i = 0; i < armoredKeys.length; i++) {
      var k = await readPublicKey(armoredKeys[i]);
      if (!seen[fingerprintOf(k)]) { seen[fingerprintOf(k)] = 1; keys.push(k); }
    }
    var payload = { v: 1, from: args.from, to: args.to, subject: args.subject, body: args.body, client_ts: Date.now() };
    var message = await pgp.createMessage({ text: JSON.stringify(payload) });
    return pgp.encrypt({ message: message, encryptionKeys: keys, signingKeys: args.signingKey, format: 'armored' });
  }

  // Returns { payload, signature: 'valid'|'invalid'|'unsigned'|'unverified' }.
  // 'unverified' = no sender key was supplied. Callers must render payload fields as text, never as HTML.
  async function decryptMessage(args) {
    // args: { armored, keys (unlocked private keys), senderPublic (armored|null) }
    var res;
    try {
      var verifyKeys = args.senderPublic ? [await readPublicKey(args.senderPublic)] : [];
      res = await pgp.decrypt({
        message: await pgp.readMessage({ armoredMessage: args.armored }),
        decryptionKeys: args.keys, verificationKeys: verifyKeys, format: 'utf8',
      });
    } catch (e) {
      throw new Error('Cannot decrypt: not encrypted to your key, or the data is damaged');
    }
    var payload;
    try { payload = validatePayload(JSON.parse(res.data)); } catch (e) { throw new Error('Malformed message contents'); }
    var signature = 'unverified';
    if (args.senderPublic) {
      signature = 'unsigned';
      if (res.signatures.length) {
        try { await res.signatures[0].verified; signature = 'valid'; } catch (e) { signature = 'invalid'; }
      }
    }
    return { payload: payload, signature: signature };
  }

  // ---- proof of work (registration) ---------------------------------------------------------------------
  function leadingZeroBits(bytes) {
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { n += 8; continue; }
      return n + Math.clz32(bytes[i]) - 24;
    }
    return n;
  }

  async function solvePow(challenge, onProgress) {
    var b64 = challenge.split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
    var bits = JSON.parse(atob(b64 + '==='.slice((b64.length + 3) % 4))).d;
    var enc = new TextEncoder(), BATCH = 2048, n = 0;
    for (;;) {
      var jobs = [];
      for (var i = 0; i < BATCH; i++) {
        jobs.push(root.crypto.subtle.digest('SHA-256', enc.encode(challenge + ':' + (n + i).toString(16))));
      }
      var digests = await Promise.all(jobs);
      for (var j = 0; j < BATCH; j++) {
        if (leadingZeroBits(new Uint8Array(digests[j])) >= bits) { return (n + j).toString(16); }
      }
      n += BATCH;
      if (onProgress) { onProgress(n); }
    }
  }

  root.TorMailCrypto = {
    MIN_PASSPHRASE: MIN_PASSPHRASE, checkPassphrase: checkPassphrase, generateKey: generateKey,
    readPublicKey: readPublicKey, fingerprintOf: fingerprintOf, formatFingerprint: formatFingerprint,
    isPassphraseProtected: isPassphraseProtected, privateFingerprint: privateFingerprint, unlock: unlock,
    encryptMessage: encryptMessage, decryptMessage: decryptMessage, solvePow: solvePow,
  };
})(typeof globalThis !== 'undefined' ? globalThis : window);
