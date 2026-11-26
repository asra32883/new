/*
 * Tor-Mail client: API calls, local key storage, and encrypted send / read.
 * Depends on crypto.js. Private keys are stored only passphrase-encrypted, and unlocked keys live in
 * memory only (a page reload means entering the passphrase again).
 */
(function (root) {
  'use strict';
  var C = root.TorMailCrypto;

  function ApiError(status, detail, retryAfter) {
    this.name = 'ApiError'; this.status = status; this.detail = detail; this.retryAfter = retryAfter || null;
    this.message = detail;
  }
  ApiError.prototype = Object.create(Error.prototype);

  function KeyChangedError(username, oldFpr, newFpr) {
    this.name = 'KeyChangedError'; this.username = username; this.oldFingerprint = oldFpr; this.newFingerprint = newFpr;
    this.message = 'The encryption key for ' + username + ' has changed since you last wrote to them.';
  }
  KeyChangedError.prototype = Object.create(Error.prototype);

  var state = { csrf: null, username: null, unlocked: [] };

  async function request(method, path, body) {
    var headers = { 'Accept': 'application/json' };
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; }
    if (method !== 'GET' && state.csrf) { headers['X-CSRF-Token'] = state.csrf; }
    var res = await fetch(path, { method: method, headers: headers, credentials: 'same-origin', cache: 'no-store',
      body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.status === 204) { return null; }
    var data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error */ }
    if (!res.ok) {
      var d = data && data.detail;
      throw new ApiError(res.status, typeof d === 'string' ? d : (Array.isArray(d) && d[0] ? d[0].msg : 'Request failed'),
        res.headers.get('Retry-After'));
    }
    return data;
  }

  // ---- account ------------------------------------------------------------------------------------------
  async function session() {
    var me = await request('GET', '/api/auth/me');
    state.csrf = me.csrf_token; state.username = me.username;
    return me;
  }
  async function register(username, password, onProgress) {
    var ch = await request('GET', '/api/auth/pow-challenge');
    var nonce = await C.solvePow(ch.challenge, onProgress);
    var me = await request('POST', '/api/auth/register', { username: username, password: password, pow_challenge: ch.challenge, pow_nonce: nonce });
    state.csrf = me.csrf_token; state.username = me.username; state.unlocked = [];
    return me;
  }
  async function login(username, password) {
    var me = await request('POST', '/api/auth/login', { username: username, password: password });
    state.csrf = me.csrf_token; state.username = me.username; state.unlocked = [];
    return me;
  }
  async function logout() {
    await request('POST', '/api/auth/logout');
    state.csrf = null; state.username = null; state.unlocked = [];   // drop unlocked keys with the session
  }

  // ---- local key storage ----------------------------------------------------------------------------------
  function storeKey(name) { return 'tormail:keys:' + name; }
  function localKeys(username) {
    try { return JSON.parse(localStorage.getItem(storeKey(username)) || '[]'); } catch (e) { return []; }
  }
  function saveLocalKeys(username, list) {
    try { localStorage.setItem(storeKey(username), JSON.stringify(list)); return true; } catch (e) { return false; }
  }
  async function addLocalKey(username, armoredPrivate) {
    if (!(await C.isPassphraseProtected(armoredPrivate))) { throw new Error('Refusing to store a private key that is not passphrase-protected'); }
    var fpr = await C.privateFingerprint(armoredPrivate), list = localKeys(username);
    var rest = [];
    for (var i = 0; i < list.length; i++) { if ((await C.privateFingerprint(list[i])) !== fpr) { rest.push(list[i]); } }
    return saveLocalKeys(username, [armoredPrivate].concat(rest));   // newest first
  }
  async function unlockLocal(passphrase) {
    var list = localKeys(state.username);
    if (!list.length) { throw new Error('No private key stored in this browser. Import your backup first.'); }
    state.unlocked = await C.unlock(list, passphrase);
    return state.unlocked.length;
  }
  function lock() { state.unlocked = []; }

  // ---- key API --------------------------------------------------------------------------------------------
  async function getMyKey() {
    try { return await request('GET', '/api/keys/me'); } catch (e) { if (e.status === 404) { return null; } throw e; }
  }
  function putMyKey(publicKey, fingerprint, encryptedPrivateKey) {
    var body = { public_key: publicKey, fingerprint: fingerprint };
    if (encryptedPrivateKey) { body.encrypted_private_key = encryptedPrivateKey; }
    return request('PUT', '/api/keys/me', body);
  }
  function deleteServerBackup() { return request('DELETE', '/api/keys/me/backup'); }
  async function fetchServerBackup() { return (await request('GET', '/api/keys/me/backup')).encrypted_private_key; }

  // Contacts pin the first key seen for each user (trust on first use). A later change is surfaced, never silent.
  function contactsKey() { return 'tormail:contacts:' + state.username; }
  function contacts() { try { return JSON.parse(localStorage.getItem(contactsKey()) || '{}'); } catch (e) { return {}; } }
  function saveContacts(c) { try { localStorage.setItem(contactsKey(), JSON.stringify(c)); } catch (e) { /* storage unavailable */ } }
  function markVerified(username, fingerprint) {
    var c = contacts(); c[username] = { fingerprint: fingerprint, verified: true }; saveContacts(c);
  }

  // opts.acceptChange: allow a changed key and re-pin it (send flow, after the user agreed).
  // opts.readOnly: never touch the pins (used when reading mail).
  async function fetchVerifiedKey(username, opts) {
    opts = opts || {};
    var rec = await request('GET', '/api/users/' + encodeURIComponent(username) + '/key');
    var key = await C.readPublicKey(rec.public_key);
    var actual = C.fingerprintOf(key);
    if (actual !== rec.fingerprint) { throw new Error('The server returned a key whose fingerprint does not match for ' + username); }
    var c = contacts(), pinned = c[username];
    var changed = !!(pinned && pinned.fingerprint !== actual);
    if (opts.readOnly) {
      return { armored: rec.public_key, fingerprint: actual, changed: changed, verified: !!(pinned && !changed && pinned.verified) };
    }
    if (changed && !opts.acceptChange) { throw new KeyChangedError(username, pinned.fingerprint, actual); }
    if (!pinned || changed) { c[username] = { fingerprint: actual, verified: false }; saveContacts(c); }
    return { armored: rec.public_key, fingerprint: actual, changed: false, verified: !!(c[username] && c[username].verified) };
  }

  // ---- mail -----------------------------------------------------------------------------------------------
  async function send(to, subject, body, opts) {
    opts = opts || {};
    if (!state.unlocked.length) { throw new Error('Unlock your key first'); }
    var mine = await getMyKey();
    if (!mine) { throw new Error('Set up your encryption key first'); }
    var myKey = await C.readPublicKey(mine.public_key);
    if (C.fingerprintOf(myKey) !== mine.fingerprint) { throw new Error('Your key on the server does not match its fingerprint'); }
    var signer = state.unlocked.filter(function (k) { return C.fingerprintOf(k) === mine.fingerprint; })[0];
    if (!signer) { throw new Error('The unlocked key is not your current key. Import the backup for your current key.'); }
    var names = to.map(function (n) { return n.trim().toLowerCase(); });
    var recips = [];
    for (var i = 0; i < names.length; i++) {
      var accept = (opts.acceptKeyChange || []).indexOf(names[i]) !== -1;
      recips.push((await fetchVerifiedKey(names[i], { acceptChange: accept })).armored);
    }
    var armored = await C.encryptMessage({ signingKey: signer, senderPublic: mine.public_key, recipientPublics: recips,
      from: state.username, to: names, subject: subject, body: body });
    return request('POST', '/api/messages', { recipients: names, ciphertext: armored });
  }

  // Decrypts one server item (from list or get). Returns text fields plus honest trust indicators.
  async function open(item, folder) {
    if (!state.unlocked.length) { throw new Error('Unlock your key first'); }
    var claimedSender = folder === 'sent' ? state.username : item.sender;
    var senderPub = null, senderVerified = false, senderChanged = false;
    if (claimedSender) {
      try {
        var k = await fetchVerifiedKey(claimedSender, { readOnly: true });
        senderPub = k.armored; senderVerified = k.verified; senderChanged = k.changed;
      } catch (e) { senderPub = null; }
    }
    var out = await C.decryptMessage({ armored: item.ciphertext, keys: state.unlocked, senderPublic: senderPub });
    var p = out.payload;
    return {
      id: item.id, subject: p.subject, body: p.body, to: p.to, from: p.from, sentAt: p.client_ts,
      signature: out.signature,                                  // 'valid' only if signed by the sender's current key
      senderKeyChanged: senderChanged,                           // sender's key differs from the one you pinned
      senderKeyVerified: senderVerified,                         // user compared the fingerprint out of band
      senderMismatch: !!claimedSender && p.from !== claimedSender,   // server says one sender, signed contents say another
    };
  }

  function list(folder, cursor, limit) {
    var q = [];
    if (cursor) { q.push('cursor=' + encodeURIComponent(cursor)); }
    if (limit) { q.push('limit=' + limit); }
    return request('GET', '/api/mailbox/' + folder + (q.length ? '?' + q.join('&') : ''));
  }

  root.TorMail = {
    ApiError: ApiError, KeyChangedError: KeyChangedError, state: state, request: request,
    session: session, register: register, login: login, logout: logout,
    localKeys: localKeys, addLocalKey: addLocalKey, unlockLocal: unlockLocal, lock: lock,
    getMyKey: getMyKey, putMyKey: putMyKey, deleteServerBackup: deleteServerBackup, fetchServerBackup: fetchServerBackup,
    fetchVerifiedKey: fetchVerifiedKey, contacts: contacts, markVerified: markVerified,
    send: send, open: open, list: list,
    del: function (folder, id) { return request('DELETE', '/api/mailbox/' + folder + '/' + id); },
    setRead: function (id, v) { return request('POST', '/api/mailbox/inbox/' + id + '/read', { is_read: v }); },
  };
})(typeof globalThis !== 'undefined' ? globalThis : window);
