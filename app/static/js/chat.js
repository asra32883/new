/*
 * Tor-Mail chat engine. Everything readable (text, replies, reactions, edits, file names, group titles, files)
 * is encrypted and signed in this browser; the server only moves ciphertext and enforces membership.
 *
 * Event kinds inside the encrypted payload (all carry the chat id, the sender and a unique id):
 *   msg   {text, reply, files:[{blob,name,mime,size}]}
 *   edit  {target, text}            honoured only if validly signed by the original sender
 *   react {target, emoji|null}      honoured only if validly signed; one reaction per person per message
 * Group titles live in an encrypted "meta" payload on the chat. Nothing decrypted is ever written to storage.
 */
(function (root) {
  'use strict';
  var M = root.TorMail, C = root.TorMailCrypto, F = root.TorFiles;
  var EMOJI = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
  var TTL_LABELS = [[0, 'Off'], [30, '30 seconds'], [300, '5 minutes'], [3600, '1 hour'], [86400, '1 day'], [604800, '1 week']];
  var LIMITS = { text: 8000, files: 6, fileBytes: 1500000 };
  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  var chats = {};            // id -> chat item from the server
  var stores = {};           // id -> { events: {seq: ev}, deleted: {seq:1}, min, max, more, busy }
  var titles = {};           // meta ciphertext -> title
  var previews = {};         // last message id -> short text
  var files = {};            // blob id -> { url, signature, mime }
  var listeners = [];
  var poll = { gen: 0, running: false, cursor: null, lastFull: 0 };

  function emit(type, id) { listeners.forEach(function (f) { try { f(type, id); } catch (e) { /* a view error must not stop syncing */ } }); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function me() { return M.state.username; }

  function uuid4() {
    var b = root.crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
    var h = Array.prototype.map.call(b, function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }

  // ---- preferences (this browser only) ---------------------------------------------------------------------
  function prefKey() { return 'tormail:prefs:' + me(); }
  function prefs() {
    var p = {};
    try { p = JSON.parse(localStorage.getItem(prefKey()) || '{}'); } catch (e) { p = {}; }
    return { receipts: p.receipts !== false };
  }
  function setPref(name, value) {
    var p = prefs(); p[name] = value;
    try { localStorage.setItem(prefKey(), JSON.stringify(p)); } catch (e) { /* storage unavailable */ }
    emit('chats');
  }
  function localReadKey() { return 'tormail:chatread:' + me(); }
  function localRead() { try { return JSON.parse(localStorage.getItem(localReadKey()) || '{}'); } catch (e) { return {}; } }
  function setLocalRead(id, seq) {
    var r = localRead(); r[id] = seq;
    try { localStorage.setItem(localReadKey(), JSON.stringify(r)); } catch (e) { /* ignore */ }
  }

  // ---- lookups ---------------------------------------------------------------------------------------------
  function list() {
    return Object.keys(chats).map(function (k) { return chats[k]; }).sort(function (a, b) { return a.updated_at < b.updated_at ? 1 : -1; });
  }
  function get(id) { return chats[id] || null; }
  function others(chat) { return chat.members.filter(function (m) { return m.username !== me(); }); }
  function title(chat) {
    if (chat.kind === 'direct') { var o = others(chat)[0]; return o ? o.username : 'Deleted account'; }
    return chat.meta_ciphertext && titles[chat.meta_ciphertext] ? titles[chat.meta_ciphertext] : 'Group chat';
  }
  function unread(chat) {
    // With read receipts off, "read" is tracked only in this browser; the server count can only be an upper bound.
    if (prefs().receipts) { return chat.unread; }
    var local = localRead()[chat.id] || 0;
    return Math.max(0, Math.min(chat.unread, chat.last_seq - local));
  }
  function unreadTotal() { return list().reduce(function (n, c) { return n + (unread(c) ? 1 : 0); }, 0); }
  function preview(chat) {
    var m = chat.last_message;
    if (!m) { return ''; }
    if (previews[m.id] !== undefined) { return previews[m.id]; }
    return m.ciphertext ? (M.state.unlocked.length ? '' : 'Locked') : 'New message';
  }
  function ttlLabel(seconds) {
    for (var i = 0; i < TTL_LABELS.length; i++) { if (TTL_LABELS[i][0] === (seconds || 0)) { return TTL_LABELS[i][1]; } }
    return seconds + ' s';
  }

  // ---- decoding --------------------------------------------------------------------------------------------
  function validEvent(p, chatId) {
    if (!p || p.v !== 1 || p.chat !== chatId || typeof p.from !== 'string' || typeof p.id !== 'string' || !UUID_RE.test(p.id)) { return false; }
    if (typeof p.ts !== 'number') { return false; }
    if (p.t === 'msg') {
      if (typeof p.text !== 'string' || p.text.length > LIMITS.text) { return false; }
      if (p.reply != null && !(typeof p.reply === 'string' && UUID_RE.test(p.reply))) { return false; }
      var fs = p.files == null ? [] : p.files;
      if (!Array.isArray(fs) || fs.length > LIMITS.files) { return false; }
      return fs.every(function (f) {
        return f && typeof f.blob === 'string' && UUID_RE.test(f.blob) && typeof f.name === 'string' && f.name.length <= 200 &&
          typeof f.mime === 'string' && f.mime.length <= 100 && Number.isInteger(f.size) && f.size >= 0;
      });
    }
    if (p.t === 'edit') { return typeof p.target === 'string' && UUID_RE.test(p.target) && typeof p.text === 'string' && p.text.length <= LIMITS.text; }
    if (p.t === 'react') { return typeof p.target === 'string' && UUID_RE.test(p.target) && (p.emoji === null || EMOJI.indexOf(p.emoji) !== -1); }
    return false;
  }

  async function decode(chatId, item) {
    var base = { seq: item.seq, sender: item.sender, expiresAt: item.expires_at ? Date.parse(item.expires_at) : null,
      createdAt: Date.parse(item.created_at), blobs: item.blobs || [], payload: null, signature: 'unverified', problem: null };
    if (!item.ciphertext) { base.problem = 'gone'; return base; }
    if (!M.state.unlocked.length) { base.problem = 'locked'; return base; }
    var sk = await M.senderKey(item.sender);
    try {
      var r = await C.decryptObject({ armored: item.ciphertext, keys: M.state.unlocked, senderPublics: sk ? [sk.armored] : [] });
      if (!validEvent(r.object, chatId)) { base.problem = 'invalid'; return base; }
      base.payload = r.object; base.signature = r.signature;
      base.senderVerified = !!(sk && sk.verified); base.senderChanged = !!(sk && sk.changed); base.senderFingerprint = sk ? sk.fingerprint : null;
      base.mismatch = !!item.sender && r.object.from !== item.sender;    // the server says one sender, the signed contents say another
    } catch (e) { base.problem = 'undecryptable'; }
    return base;
  }

  function storeFor(id) {
    return stores[id] || (stores[id] = { events: {}, deleted: {}, min: Infinity, max: 0, more: false, busy: Promise.resolve(), loaded: false });
  }
  function serialize(id, fn) {            // one sync operation per chat at a time
    var s = storeFor(id), run = s.busy.then(fn, fn);
    s.busy = run.catch(function () { /* errors go to the caller of run */ });
    return run;
  }
  async function absorb(id, items, deletedSeqs) {
    var s = storeFor(id);
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (s.events[it.seq] && s.events[it.seq].payload) { continue; }
      s.events[it.seq] = await decode(id, it);
      s.min = Math.min(s.min, it.seq); s.max = Math.max(s.max, it.seq);
    }
    s.deleted = {};
    (deletedSeqs || []).forEach(function (q) { s.deleted[q] = 1; delete s.events[q]; });
  }

  async function loadLatest(id) {
    return serialize(id, async function () {
      var s = storeFor(id), q = s.loaded ? '?after_seq=' + s.max + '&limit=100' : '?limit=40';
      var res = await M.request('GET', '/api/chats/' + id + '/messages' + q);
      await absorb(id, res.items, res.deleted_seqs);
      if (!s.loaded) { s.loaded = true; s.more = res.has_more; }
      emit('chat', id);
      return res.items.length;
    });
  }
  async function loadOlder(id) {
    return serialize(id, async function () {
      var s = storeFor(id);
      if (!s.more) { return 0; }
      var res = await M.request('GET', '/api/chats/' + id + '/messages?before_seq=' + s.min + '&limit=40');
      await absorb(id, res.items, res.deleted_seqs);
      s.more = res.has_more;
      emit('chat', id);
      return res.items.length;
    });
  }
  // Re-decrypt everything that could not be read earlier (after unlocking the key, or a sender key became available).
  async function redecode() {
    var ids = Object.keys(stores);
    for (var i = 0; i < ids.length; i++) {
      var s = stores[ids[i]];
      var pending = Object.keys(s.events).filter(function (q) { return !s.events[q].payload; });
      if (!pending.length) { continue; }
      s.loaded = false; s.events = {}; s.min = Infinity; s.max = 0;
      try { await loadLatest(ids[i]); } catch (e) { /* retried on the next open */ }
    }
  }

  // ---- timeline ---------------------------------------------------------------------------------------------
  function timeline(id, now) {
    now = now || Date.now();
    var s = stores[id], chat = chats[id];
    if (!s || !chat) { return []; }
    var seqs = Object.keys(s.events).map(Number).sort(function (a, b) { return a - b; });
    var out = [], byId = {}, myName = me();
    seqs.forEach(function (seq) {
      var ev = s.events[seq];
      if (ev.expiresAt && ev.expiresAt <= now) { return; }
      var p = ev.payload;
      if (!p) { out.push({ key: 's' + seq, seq: seq, problem: ev.problem, from: ev.sender, mine: ev.sender === myName, ts: ev.createdAt }); return; }
      var trusted = ev.signature === 'valid' && !ev.mismatch;
      if (p.t === 'msg') {
        if (byId[p.id]) { return; }                          // a replayed copy of an earlier message
        var b = { key: 'm' + seq, seq: seq, id: p.id, from: ev.sender || p.from, mine: (ev.sender || p.from) === myName, text: p.text, ts: p.ts,
          files: (p.files || []).filter(function (f) { return ev.blobs.indexOf(f.blob) !== -1; }), reply: p.reply || null, reactions: {}, edited: false,
          signature: ev.signature, mismatch: !!ev.mismatch, senderChanged: !!ev.senderChanged, senderVerified: !!ev.senderVerified, expiresAt: ev.expiresAt };
        byId[p.id] = b; out.push(b);
      } else if (p.t === 'edit') {
        var t = byId[p.target];
        if (t && trusted && t.from === (ev.sender || p.from)) { t.text = p.text; t.edited = true; }
      } else if (p.t === 'react') {
        var r = byId[p.target];
        if (r && trusted) { if (p.emoji) { r.reactions[ev.sender || p.from] = p.emoji; } else { delete r.reactions[ev.sender || p.from]; } }
      }
    });
    out.forEach(function (b) {
      if (b.reply) { var q = byId[b.reply]; b.replyTo = q ? { from: q.from, text: q.text, files: q.files.length } : null; }
      if (b.mine && b.seq !== undefined) { b.readBy = others(chat).filter(function (m) { return m.last_read_seq >= b.seq; }).map(function (m) { return m.username; }); }
    });
    return out.filter(function (b) { return b.problem || b.id; });
  }
  function hasMore(id) { return !!(stores[id] && stores[id].more); }
  function deletedCount(id) { return stores[id] ? Object.keys(stores[id].deleted).length : 0; }

  // ---- titles and previews ----------------------------------------------------------------------------------
  async function decodeTitles() {
    if (!M.state.unlocked.length) { return; }
    var changed = false;
    var all = list();
    for (var i = 0; i < all.length; i++) {
      var c = all[i];
      if (c.kind === 'group' && c.meta_ciphertext && titles[c.meta_ciphertext] === undefined) {
        try {
          var keys = [];
          for (var j = 0; j < c.members.length; j++) { var k = await M.senderKey(c.members[j].username); if (k) { keys.push(k.armored); } }
          var r = await C.decryptObject({ armored: c.meta_ciphertext, keys: M.state.unlocked, senderPublics: keys });
          titles[c.meta_ciphertext] = r.object.t === 'meta' && typeof r.object.title === 'string' && r.signature === 'valid'
            ? r.object.title.slice(0, 80) : 'Group chat';
        } catch (e) { titles[c.meta_ciphertext] = 'Group chat'; }
        changed = true;
      }
      var m = c.last_message;
      if (m && m.ciphertext && previews[m.id] === undefined) {
        var ev = await decode(c.id, m);
        var text = '';
        if (ev.payload && ev.payload.t === 'msg') { text = ev.payload.text || (ev.payload.files && ev.payload.files.length ? 'Attachment' : ''); }
        else if (ev.payload) { text = 'Message'; } else if (ev.problem === 'undecryptable') { text = 'Cannot decrypt'; }
        previews[m.id] = (ev.payload && ev.payload.from !== m.sender ? 'Unverified: ' : (ev.payload && ev.payload.from === me() ? 'You: ' : '')) + text.slice(0, 120);
        changed = true;
      }
    }
    if (changed) { emit('chats'); }
  }

  // ---- syncing ----------------------------------------------------------------------------------------------
  function apply(items) {
    var touched = [];
    items.forEach(function (it) {
      var prev = chats[it.id];
      chats[it.id] = it;
      if (!prev || prev.rev !== it.rev) { touched.push(it.id); }
    });
    if (items.length) { emit('chats'); }
    touched.forEach(function (id) {
      if (stores[id] && stores[id].loaded) { loadLatest(id).catch(function () { /* next poll retries */ }); } else { emit('chat', id); }
    });
    decodeTitles().catch(function () { /* titles are cosmetic */ });
  }
  async function refreshAll() {
    var res = await M.request('GET', '/api/chats');
    var seen = {};
    res.items.forEach(function (it) { seen[it.id] = 1; });
    Object.keys(chats).forEach(function (id) { if (!seen[id]) { delete chats[id]; delete stores[id]; emit('gone', id); } });
    apply(res.items);
    poll.cursor = res.cursor; poll.lastFull = Date.now();
    emit('chats');
  }
  async function refreshChat(id) {
    var c = await M.request('GET', '/api/chats/' + id);
    chats[id] = c; emit('chats'); emit('chat', id);
    return c;
  }
  async function start() {
    if (poll.running) { return; }
    var gen = ++poll.gen; poll.running = true;
    var backoff = 3000;
    try { await refreshAll(); } catch (e) { if (e && e.status === 401) { poll.running = false; return; } }
    while (poll.running && poll.gen === gen) {
      try {
        if (Date.now() - poll.lastFull > 60000) { await refreshAll(); }
        var res = await M.request('GET', '/api/chats?wait=25&after=' + encodeURIComponent(poll.cursor || ''));
        if (poll.gen !== gen) { return; }
        poll.cursor = res.cursor; apply(res.items); backoff = 3000;
        if (res.full) { await refreshAll(); }          // a chat vanished (removed from a group): re-read the whole list
      } catch (e) {
        if (poll.gen !== gen) { return; }
        if (e && e.status === 401) { poll.running = false; emit('signedout'); return; }
        await sleep(backoff); backoff = Math.min(backoff * 2, 30000);
      }
    }
  }
  function stop() {
    poll.running = false; poll.gen++; poll.cursor = null;
    chats = {}; stores = {}; titles = {}; previews = {}; revokeFiles();
    emit('chats');
  }

  // ---- sending ----------------------------------------------------------------------------------------------
  async function prepare(chatId, opts) {
    var id = await M.identity(), c = chats[chatId];
    var names = c.members.map(function (m) { return m.username; }).filter(function (n) { return n !== me(); });
    if (!names.length) { throw new Error('There is nobody else in this chat any more.'); }
    var pubs = (await M.recipientKeys(names, { accept: opts && opts.acceptKeyChange })).concat([id.publicKey]);
    return { id: id, pubs: pubs };
  }
  async function post(chatId, kind, fields, opts) {
    opts = opts || {};
    for (var attempt = 0; ; attempt++) {
      var c = chats[chatId];
      if (!c) { throw new Error('This chat no longer exists.'); }
      var prep = await prepare(chatId, opts), blobIds = [], fmeta = [];
      var input = opts.files || [];
      if (input.length > LIMITS.files) { throw new Error('At most ' + LIMITS.files + ' files per message.'); }
      for (var i = 0; i < input.length; i++) {
        var raw = new Uint8Array(await input[i].arrayBuffer());
        if (raw.length > LIMITS.fileBytes) { throw new Error(F.safeName(input[i].name) + ' is larger than ' + Math.round(LIMITS.fileBytes / 1000000 * 10) / 10 + ' MB.'); }
        var cleaned = F.clean(raw);
        if (!cleaned.ok) { throw new Error(F.safeName(input[i].name) + ' looks like an image but could not be cleaned of metadata, so it was not sent.'); }
        var enc = await C.encryptBytes({ signingKey: prep.id.signer, publics: prep.pubs, bytes: cleaned.bytes });
        var up = await M.request('POST', '/api/chats/' + chatId + '/blobs', enc);
        blobIds.push(up.id);
        fmeta.push({ blob: up.id, name: F.safeName(input[i].name), mime: cleaned.mime || 'application/octet-stream', size: cleaned.bytes.length });
      }
      var payload = Object.assign({ v: 1, t: kind, id: uuid4(), chat: chatId, from: me(), ts: Date.now() }, fields);
      if (kind === 'msg') { payload.files = fmeta; }
      var armored = await C.encryptObject({ signingKey: prep.id.signer, publics: prep.pubs, object: payload });
      try {
        var item = await M.request('POST', '/api/chats/' + chatId + '/messages', { ciphertext: armored, members_version: c.members_version, blob_ids: blobIds });
        var s = storeFor(chatId);
        s.events[item.seq] = { seq: item.seq, sender: me(), expiresAt: item.expires_at ? Date.parse(item.expires_at) : null, createdAt: Date.parse(item.created_at),
          blobs: item.blobs || [], payload: payload, signature: 'valid', problem: null, senderVerified: true };
        s.max = Math.max(s.max, item.seq);
        c.last_seq = Math.max(c.last_seq, item.seq); c.my_last_read_seq = c.last_seq;
        emit('chat', chatId); emit('chats');
        return item;
      } catch (e) {
        if (e && e.status === 409 && e.detail === 'members_changed' && attempt === 0) { await refreshChat(chatId); continue; }   // re-encrypt to the new member set
        throw e;
      }
    }
  }
  function sendText(chatId, text, opts) {
    opts = opts || {};
    if (!text.trim() && !(opts.files && opts.files.length)) { return Promise.reject(new Error('Write a message or attach a file.')); }
    if (text.length > LIMITS.text) { return Promise.reject(new Error('Message is too long.')); }
    return post(chatId, 'msg', { text: text, reply: opts.reply || null }, opts);
  }
  function edit(chatId, msgId, text, opts) {
    if (!text.trim() || text.length > LIMITS.text) { return Promise.reject(new Error('Message text is empty or too long.')); }
    return post(chatId, 'edit', { target: msgId, text: text }, opts);
  }
  function react(chatId, msgId, emoji, opts) { return post(chatId, 'react', { target: msgId, emoji: emoji }, opts); }
  async function removeMessage(chatId, seq) {
    await M.request('DELETE', '/api/chats/' + chatId + '/messages/' + seq);
    var s = storeFor(chatId); delete s.events[seq]; s.deleted[seq] = 1;
    emit('chat', chatId);
  }

  // ---- reading state ----------------------------------------------------------------------------------------
  var readTimers = {};
  function markRead(chatId) {
    var c = chats[chatId];
    if (!c || c.last_seq <= (prefs().receipts ? c.my_last_read_seq : (localRead()[chatId] || 0))) { return; }
    var upto = c.last_seq;
    if (!prefs().receipts) { setLocalRead(chatId, upto); emit('chats'); return; }
    c.my_last_read_seq = upto; c.unread = 0; emit('chats');
    clearTimeout(readTimers[chatId]);
    readTimers[chatId] = setTimeout(function () { M.request('POST', '/api/chats/' + chatId + '/read', { upto_seq: upto }).catch(function () { /* retried next time */ }); }, 400);
  }

  // ---- creating and managing chats --------------------------------------------------------------------------
  async function metaFor(titleText, names, opts) {
    var id = await M.identity();
    var pubs = (await M.recipientKeys(names.filter(function (n) { return n !== me(); }), { accept: opts && opts.acceptKeyChange })).concat([id.publicKey]);
    return C.encryptObject({ signingKey: id.signer, publics: pubs, object: { v: 1, t: 'meta', title: titleText, by: me(), ts: Date.now() } });
  }
  async function createDirect(username) {
    await M.identity();
    var c = await M.request('POST', '/api/chats', { kind: 'direct', username: username.trim().toLowerCase() });
    chats[c.id] = c; emit('chats');
    return c;
  }
  async function createGroup(titleText, names, opts) {
    var clean = Array.from(new Set(names.map(function (n) { return n.trim().toLowerCase(); }).filter(Boolean)));
    if (!titleText.trim()) { throw new Error('Give the group a name.'); }
    var meta = await metaFor(titleText.trim().slice(0, 80), clean.concat([me()]), opts);
    var c = await M.request('POST', '/api/chats', { kind: 'group', members: clean, meta_ciphertext: meta });
    chats[c.id] = c; titles[c.meta_ciphertext] = titleText.trim().slice(0, 80); emit('chats');
    return c;
  }
  async function addMembers(chatId, names, opts) {
    var c = await refreshChat(chatId);
    var current = titles[c.meta_ciphertext];
    if (!current) { await decodeTitles(); current = titles[c.meta_ciphertext]; }
    if (!current) { throw new Error('Unlock your key so the group name can be re-encrypted for the new members.'); }
    var clean = names.map(function (n) { return n.trim().toLowerCase(); }).filter(Boolean);
    var all = c.members.map(function (m) { return m.username; }).concat(clean);
    var meta = await metaFor(current, Array.from(new Set(all)), opts);
    await M.request('POST', '/api/chats/' + chatId + '/members', { usernames: clean, members_version: c.members_version, meta_ciphertext: meta });
    return refreshChat(chatId);
  }
  async function removeMember(chatId, username) {
    var c = await refreshChat(chatId);
    await M.request('DELETE', '/api/chats/' + chatId + '/members/' + encodeURIComponent(username) + (username === me() ? '' : '?members_version=' + c.members_version));
    if (username === me()) { delete chats[chatId]; delete stores[chatId]; emit('gone', chatId); emit('chats'); return null; }
    return refreshChat(chatId);
  }
  async function setTtl(chatId, seconds) {
    await M.request('PUT', '/api/chats/' + chatId + '/ttl', { ttl_seconds: seconds || null });
    return refreshChat(chatId);
  }
  async function hide(chatId) {
    await M.request('POST', '/api/chats/' + chatId + '/hide');
    delete chats[chatId]; delete stores[chatId]; emit('gone', chatId); emit('chats');
  }

  // ---- files --------------------------------------------------------------------------------------------------
  async function fileURL(chatId, bubble, f) {
    if (files[f.blob]) { return files[f.blob]; }
    var data = await M.requestBytes('/api/chats/' + chatId + '/blobs/' + f.blob);
    var sk = await M.senderKey(bubble.from);
    var dec = await C.decryptBytes({ data: data, keys: M.state.unlocked, senderPublics: sk ? [sk.armored] : [] });
    var sniffed = F.sniff(dec.bytes);
    var previewable = !!(sniffed && F.PREVIEW[sniffed]);
    // The browser is only told a type when WE recognise the bytes as a safe image; everything else is opaque data.
    var blob = new Blob([dec.bytes], { type: previewable ? sniffed : 'application/octet-stream' });
    files[f.blob] = { url: URL.createObjectURL(blob), signature: dec.signature, previewable: previewable, size: dec.bytes.length };
    return files[f.blob];
  }
  function revokeFiles() {
    Object.keys(files).forEach(function (k) { try { URL.revokeObjectURL(files[k].url); } catch (e) { /* ignore */ } });
    files = {};
  }

  M.onChange(function () {
    if (!M.state.username) { return; }
    if (M.state.unlocked.length) { redecode().then(decodeTitles).catch(function () { /* cosmetic */ }); }
    else { revokeFiles(); titles = {}; previews = {}; Object.keys(stores).forEach(function (k) { delete stores[k]; }); emit('chats'); emit('locked'); }
  });

  root.TorChat = {
    EMOJI: EMOJI, TTL_LABELS: TTL_LABELS, LIMITS: LIMITS,
    onChange: function (f) { listeners.push(f); return function () { listeners = listeners.filter(function (x) { return x !== f; }); }; },
    start: start, stop: stop, refreshAll: refreshAll, refreshChat: refreshChat,
    list: list, get: get, title: title, others: others, unread: unread, unreadTotal: unreadTotal, preview: preview, ttlLabel: ttlLabel,
    prefs: prefs, setPref: setPref,
    loadLatest: loadLatest, loadOlder: loadOlder, timeline: timeline, hasMore: hasMore, deletedCount: deletedCount,
    sendText: sendText, edit: edit, react: react, removeMessage: removeMessage, markRead: markRead,
    createDirect: createDirect, createGroup: createGroup, addMembers: addMembers, removeMember: removeMember, setTtl: setTtl, hide: hide,
    fileURL: fileURL, cachedFile: function (blobId) { return !!files[blobId]; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : window);
