/*
 * Chat views: chat list, conversation, group info, new chat. Registered into the router by app.js.
 * Same safety rule as app.js: anything that came from another person (names, text, file names, reactions) is assigned
 * with textContent only, never as markup. Markup comes from the <template> elements in views.html.
 */
(function () {
  'use strict';
  var M = window.TorMail, T = window.TorChat, F = window.TorFiles, C = window.TorMailCrypto;

  window.TorChatUI = { install: function (h) {
    var $ = h.$, role = h.role, clone = h.clone, clear = h.clear, el = h.el, say = h.say;

    // ---- small helpers ----------------------------------------------------------------------------------
    function sameDay(a, b) { return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate(); }
    function pad(n) { return (n < 10 ? '0' : '') + n; }
    function clock(ts) { var d = new Date(ts); return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
    function short(ts) {
      var d = new Date(ts), now = new Date();
      if (isNaN(d)) { return ''; }
      return sameDay(d, now) ? clock(ts) : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
    function dayLabel(ts) {
      var d = new Date(ts), now = new Date(), y = new Date(now.getTime() - 86400000);
      return sameDay(d, now) ? 'Today' : sameDay(d, y) ? 'Yesterday' : d.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
    }
    function avatar(node, name) {
      var hue = 0, i;
      for (i = 0; i < name.length; i++) { hue = (hue * 31 + name.charCodeAt(i)) % 360; }
      node.textContent = (name.charAt(0) || '?').toUpperCase();
      node.style.backgroundColor = 'hsl(' + hue + ' 45% 36%)';       // CSSOM styling is allowed under the strict CSP
    }
    function names(text) { return Array.from(new Set(text.split(/[\s,;]+/).map(function (n) { return n.trim().toLowerCase(); }).filter(Boolean))); }
    function coarse() { return !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches); }

    // Runs fn(acceptList). If a contact's key changed since you first saw it, asks (in the given notice box) and retries.
    async function withKeyConfirm(box, fn) {
      var accept = [];
      for (var i = 0; i < 10; i++) {
        try { return await fn(accept); } catch (e) {
          if (!(e && e.name === 'KeyChangedError')) { throw e; }
          var ok = await ask(box, e);
          if (!ok) { throw new Error('Cancelled: ' + e.username + '\'s key changed and you did not accept it.'); }
          accept = accept.concat([e.username]);
        }
      }
      throw new Error('Too many key changes.');
    }
    function ask(box, err) {
      return new Promise(function (resolve) {
        role(box, 'keynote-text').textContent = err.username + '\'s encryption key is different from the one you saw before. Old fingerprint: ' +
          C.formatFingerprint(err.oldFingerprint) + '. New fingerprint: ' + C.formatFingerprint(err.newFingerprint) +
          '. This is normal if they made a new key, but a server swapping keys would look the same. Compare fingerprints with them another way if it matters.';
        box.hidden = false;
        function done(v) { box.hidden = true; resolve(v); }
        role(box, 'keynote-yes').onclick = function () { done(true); };
        role(box, 'keynote-no').onclick = function () { done(false); };
        role(box, 'keynote-yes').focus();
      });
    }

    // ---- chat list + conversation -------------------------------------------------------------------------
    async function viewChats(args) {
      var id = args[0] || null;
      var node = clone('v-chats');
      node.setAttribute('data-mode', id ? 'thread' : 'list');
      var list = role(node, 'list'), empty = role(node, 'empty'), main = role(node, 'main'), thread = null;
      h.mountUnlock(role(node, 'unlock'));
      if (!T.list().length) { try { await T.refreshAll(); } catch (e) { if (e && e.status === 401) { throw e; } } }

      function renderList() {
        var items = T.list();
        clear(list);
        items.forEach(function (c) {
          var li = clone('t-chatrow'), a = $('a', li), name = T.title(c), n = T.unread(c);
          a.href = '/chats/' + c.id;
          if (c.id === id) { a.setAttribute('aria-current', 'page'); }
          role(li, 'name').textContent = name;
          avatar(role(li, 'avatar'), c.kind === 'group' ? name : name);
          var t = c.last_message ? c.last_message.created_at : c.updated_at;
          role(li, 'time').textContent = short(t);
          role(li, 'preview').textContent = T.preview(c);
          var b = role(li, 'unread');
          if (n) { b.hidden = false; b.textContent = n > 99 ? '99+' : String(n); b.setAttribute('aria-label', n + ' unread'); }
          if (n) { li.classList.add('has-unread'); }
          list.appendChild(li);
        });
        empty.hidden = items.length > 0;
      }
      renderList();

      var off = T.onChange(function (type, cid) {
        if (type === 'gone' && cid === id) { h.navigate('/chats'); return; }
        if (type === 'chats' || type === 'gone') { renderList(); }
        if (thread && (type === 'chats' || (type === 'chat' && cid === id))) { thread.update(); }
      });

      if (!id) { main.appendChild(clone('v-chat-empty')); }
      else {
        var chat = T.get(id);
        if (!chat) { try { chat = await T.refreshChat(id); } catch (e) { if (e && e.status === 401) { throw e; } } }
        if (!chat) { main.appendChild(el('p', 'notice warn', 'This chat does not exist, or you are not a member of it.')); }
        else { thread = openThread(main, id); }
      }
      return { node: node, title: id && T.get(id) ? T.title(T.get(id)) : 'Chats',
        cleanup: function () { off(); if (thread) { thread.dispose(); } },
        after: function () { if (thread) { thread.ready(); } } };
    }

    function openThread(main, id) {
      var node = clone('v-thread');
      main.appendChild(node);
      var log = role(node, 'log'), body = role(node, 'body'), form = role(node, 'composer'), ta = role(node, 'text'), sendBtn = role(node, 'send');
      var fileInput = role(node, 'file'), older = role(node, 'older');
      var state = { reply: null, editing: null, files: [], picker: null, confirm: null, bubbles: {}, busy: false, infoOpen: false, lastExpiring: false };
      var timers = [];
      h.mountUnlock(role(node, 'unlock'));

      function chat() { return T.get(id); }
      function atBottom() { return window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 140; }
      function toBottom() { window.scrollTo(0, document.documentElement.scrollHeight); }
      function fail(e) { h.onError(e); }

      // -- header, member-change notice, composer state
      function renderHeader() {
        var c = chat(); if (!c) { return; }
        var name = T.title(c), sub = c.kind === 'group'
          ? c.members.length + ' members: ' + c.members.map(function (m) { return m.username; }).slice(0, 5).join(', ') + (c.members.length > 5 ? '...' : '')
          : 'End-to-end encrypted';
        if (c.ttl_seconds) { sub += ' · Messages disappear after ' + T.ttlLabel(c.ttl_seconds); }
        role(node, 'title').textContent = name;
        role(node, 'sub').textContent = sub;
        avatar(role(node, 'avatar'), name);
        document.title = name + ' - Tor-Mail';
        var unlocked = M.state.unlocked.length > 0, alone = T.others(c).length === 0;
        ta.disabled = !unlocked || alone; sendBtn.disabled = ta.disabled || state.busy; role(node, 'attach').disabled = ta.disabled;
        ta.placeholder = alone ? 'Nobody else is in this chat' : (unlocked ? 'Write a message' : 'Unlock your key to write');
      }
      function membersKey() { return 'tormail:members:' + M.state.username + ':' + id; }
      function checkMembers() {
        var c = chat(), note = role(node, 'membernote'); if (!c) { return; }
        var now = c.members.map(function (m) { return m.username; }).sort(), old = null;
        try { old = JSON.parse(localStorage.getItem(membersKey()) || 'null'); } catch (e) { old = null; }
        if (!old) { remember(); return; }
        var added = now.filter(function (n) { return old.indexOf(n) === -1; }), removed = old.filter(function (n) { return now.indexOf(n) === -1; });
        if (!added.length && !removed.length) { note.hidden = true; return; }
        clear(note);
        note.appendChild(el('p', '', 'Members changed since you last looked: ' + (added.length ? added.join(', ') + ' joined. ' : '') + (removed.length ? removed.join(', ') + ' left or were removed. ' : '') +
          'The service decides who is on this list, so check that you expect these people.'));
        var ok = el('button', 'secondary', 'I know about this'); ok.type = 'button';
        ok.addEventListener('click', function () { remember(); note.hidden = true; });
        note.appendChild(ok); note.hidden = false;
      }
      function remember() {
        var c = chat(); if (!c) { return; }
        try { localStorage.setItem(membersKey(), JSON.stringify(c.members.map(function (m) { return m.username; }).sort())); } catch (e) { /* storage unavailable */ }
      }

      // -- messages
      function renderFile(box, b, f) {
        var wrap = el('div', 'file'), label = el('span', 'file-name', f.name + ' (' + h.fmtSize(f.size) + ')');
        var isImage = !!F.PREVIEW[f.mime];
        function show(res) {
          clear(wrap);
          if (res.previewable) { var img = el('img', 'bubble-img'); img.src = res.url; img.alt = f.name; img.loading = 'lazy'; wrap.appendChild(img); }
          var a = el('a', 'file-link', res.previewable ? 'Save' : 'Download ' + f.name + ' (' + h.fmtSize(f.size) + ')');
          a.href = res.url; a.download = F.safeName(f.name); wrap.appendChild(a);
          if (res.signature !== 'valid') { wrap.appendChild(el('p', 'bubble-warn', 'This file\'s signature could not be verified.')); }
        }
        function load() {
          var btn = wrap.querySelector('button'); if (btn) { btn.disabled = true; btn.textContent = 'Decrypting...'; }
          T.fileURL(id, b, f).then(show).catch(function () { clear(wrap); wrap.appendChild(el('p', 'bubble-warn', 'Could not open ' + f.name + '.')); });
        }
        wrap.appendChild(label);
        if (!M.state.unlocked.length) { box.appendChild(wrap); return; }
        var auto = isImage && f.size <= 400000;
        if (auto || T.cachedFile(f.blob)) { load(); }
        else {
          var btn = el('button', 'secondary small', isImage ? 'Show image' : 'Download'); btn.type = 'button'; btn.addEventListener('click', load);
          wrap.appendChild(btn);
        }
        box.appendChild(wrap);
      }

      function fillBubble(li, b, c) {
        var art = $('.bubble', li);
        art.classList.add(b.mine ? 'mine' : 'theirs');
        li.classList.add(b.mine ? 'row-mine' : 'row-theirs');
        li.setAttribute('data-key', b.key);
        var fromEl = role(li, 'from');
        if (!b.mine && c.kind === 'group') { fromEl.textContent = b.from || 'Deleted account'; } else { fromEl.hidden = true; }
        var actions = $('.bubble-actions', li);
        if (b.problem) {
          var msg = { locked: 'Locked. Unlock your key to read this message.', undecryptable: 'This message was not encrypted to your key, or it is damaged.',
            invalid: 'This message has an unexpected format and was ignored.', gone: 'Message removed.' }[b.problem];
          role(li, 'text').textContent = msg; role(li, 'text').classList.add('muted');
          role(li, 'time').textContent = b.ts ? clock(b.ts) : '';
          actions.hidden = true; return;
        }
        state.bubbles[b.key] = b;
        var q = role(li, 'reply');
        if (b.reply) {
          q.hidden = false;
          q.textContent = b.replyTo ? (b.replyTo.from + ': ' + (b.replyTo.text ? b.replyTo.text.slice(0, 120) : (b.replyTo.files ? 'Attachment' : ''))) : 'Original message is not available';
        }
        var text = role(li, 'text');
        if (b.text) { text.textContent = b.text; } else { text.hidden = true; }
        b.files.forEach(function (f) { renderFile(role(li, 'files'), b, f); });
        var t = role(li, 'time'); t.textContent = clock(b.ts); t.title = h.fmt(b.ts); t.setAttribute('datetime', new Date(b.ts).toISOString());
        if (b.edited) { role(li, 'edited').hidden = false; }
        if (b.expiresAt) { var ex = role(li, 'expires'); ex.hidden = false; ex.textContent = 'disappears ' + short(b.expiresAt) + ' ' + clock(b.expiresAt); state.lastExpiring = true; }
        if (b.mine) {
          var seen = b.readBy || [];
          role(li, 'ticks').textContent = c.kind === 'direct' ? (seen.length ? '✓✓ Read' : '✓ Sent') : ('✓ Sent' + (seen.length ? ' · Seen by ' + seen.length : ''));
          if (seen.length && c.kind === 'group') { role(li, 'ticks').title = 'Seen by ' + seen.join(', '); }
        }
        var warn = role(li, 'warn'), w = '';
        if (!b.mine) {
          if (b.mismatch) { w = 'Sender mismatch: the service says this came from ' + (b.from || 'an unknown account') + ' but the signed contents say otherwise. Do not trust it.'; }
          else if (b.signature === 'invalid') { w = 'Signature invalid: this was not signed by ' + b.from + '\'s key. Do not trust who sent it.'; }
          else if (b.signature === 'unsigned') { w = 'Not signed: the sender cannot be confirmed.'; }
          else if (b.signature === 'unverified') { w = 'The sender\'s key is unavailable, so the sender could not be checked.'; }
          else if (b.senderChanged) { w = b.from + '\'s key changed since you first saw it.'; }
        }
        if (w) { warn.hidden = false; warn.textContent = w; }
        var rx = role(li, 'reactions'), groups = {};
        Object.keys(b.reactions).forEach(function (u) { (groups[b.reactions[u]] = groups[b.reactions[u]] || []).push(u); });
        var mineR = b.reactions[M.state.username];
        Object.keys(groups).forEach(function (e) {
          var chip = el('button', 'chip', e + ' ' + groups[e].length); chip.type = 'button';
          chip.setAttribute('aria-pressed', mineR === e ? 'true' : 'false'); chip.setAttribute('aria-label', e + ' from ' + groups[e].join(', '));
          chip.setAttribute('data-act', 'toggle-react'); chip.setAttribute('data-emoji', e);
          rx.appendChild(chip); rx.hidden = false;
        });
        var picker = role(li, 'picker');
        if (state.picker === b.key) {
          T.EMOJI.forEach(function (e) {
            var pb = el('button', 'chip', e); pb.type = 'button'; pb.setAttribute('data-act', 'pick'); pb.setAttribute('data-emoji', e);
            pb.setAttribute('aria-label', 'React with ' + e); picker.appendChild(pb);
          });
          picker.hidden = false;
        }
        $('[data-act=react]', li).setAttribute('aria-expanded', state.picker === b.key ? 'true' : 'false');
        if (b.mine) {
          $('[data-act=edit]', li).hidden = false;
          var del = $('[data-act=delete]', li); del.hidden = false;
          if (state.confirm === b.key) { del.textContent = 'Confirm delete'; del.classList.add('danger-text'); }
        }
      }

      function renderLog() {
        var c = chat(); if (!c) { return; }
        var wasBottom = atBottom(), focusSpec = null, a = document.activeElement;
        if (a && log.contains(a)) { var row = a.closest('li[data-key]'); if (row) { focusSpec = [row.getAttribute('data-key'), a.getAttribute('data-act'), a.getAttribute('data-emoji')]; } }
        var tl = T.timeline(id), lastDay = null;
        clear(log); state.bubbles = {}; state.lastExpiring = false;
        tl.forEach(function (b) {
          if (b.ts) {
            var d = new Date(b.ts);
            if (!lastDay || !sameDay(lastDay, d)) { var sep = el('li', 'daysep'); sep.appendChild(el('span', '', dayLabel(b.ts))); log.appendChild(sep); lastDay = d; }
          }
          var li = clone('t-bubble'); fillBubble(li, b, c); log.appendChild(li);
        });
        role(node, 'empty').hidden = tl.length > 0 || !M.state.unlocked.length;
        older.hidden = !T.hasMore(id);
        if (focusSpec) {
          var sel = 'li[data-key="' + focusSpec[0] + '"] ' + (focusSpec[1] ? '[data-act="' + focusSpec[1] + '"]' + (focusSpec[2] ? '[data-emoji="' + focusSpec[2] + '"]' : '') : '');
          var target = log.querySelector(sel); if (target) { target.focus(); }
        }
        if (wasBottom) { toBottom(); }
        maybeRead();
      }
      function maybeRead() { if (!document.hidden && M.state.unlocked.length) { T.markRead(id); } }

      // -- actions on bubbles (event delegation)
      log.addEventListener('click', function (ev) {
        var btn = ev.target.closest('[data-act]'); if (!btn) { return; }
        var li = btn.closest('li[data-key]'), b = li && state.bubbles[li.getAttribute('data-key')]; if (!b) { return; }
        var act = btn.getAttribute('data-act');
        if (act === 'reply') { state.reply = b; state.editing = null; renderBars(); ta.focus(); }
        else if (act === 'react') { state.picker = state.picker === b.key ? null : b.key; renderLog(); }
        else if (act === 'pick' || act === 'toggle-react') {
          var e = btn.getAttribute('data-emoji'), mineR = b.reactions[M.state.username];
          state.picker = null;
          withKeyConfirm(role(node, 'keynote'), function (accept) { return T.react(id, b.id, mineR === e ? null : e, { acceptKeyChange: accept }); }).catch(fail);
        }
        else if (act === 'edit') { state.editing = b; state.reply = null; ta.value = b.text; renderBars(); ta.focus(); }
        else if (act === 'delete') {
          if (state.confirm !== b.key) { state.confirm = b.key; renderLog(); clearTimeout(timers.confirm); timers.confirm = setTimeout(function () { state.confirm = null; renderLog(); }, 5000); return; }
          state.confirm = null;
          T.removeMessage(id, b.seq).then(function () { say('Message deleted for everyone.'); renderLog(); }).catch(fail);
        }
      });

      function renderBars() {
        var rb = role(node, 'replybar');
        if (state.editing) { rb.hidden = false; role(node, 'replytext').textContent = 'Editing your message'; }
        else if (state.reply) { rb.hidden = false; role(node, 'replytext').textContent = 'Replying to ' + (state.reply.from || 'a message') + ': ' + (state.reply.text || 'Attachment').slice(0, 80); }
        else { rb.hidden = true; }
        var bar = role(node, 'attachbar'), note = role(node, 'attachnote');
        clear(bar);
        state.files.forEach(function (f, i) {
          var li = el('li', '', f.name + ' (' + h.fmtSize(f.size) + ') ');
          var rm = el('button', 'linklike', 'Remove'); rm.type = 'button'; rm.setAttribute('aria-label', 'Remove ' + f.name);
          rm.addEventListener('click', function () { state.files.splice(i, 1); renderBars(); });
          li.appendChild(rm); bar.appendChild(li);
        });
        bar.hidden = !state.files.length; note.hidden = !state.files.length;
        if (state.files.length) {
          var img = state.files.some(function (f) { return /^image\/(jpeg|png|gif|webp)$/.test(f.type); });
          note.textContent = img ? 'Photos: location, camera and time details are removed before sending. Other files are sent exactly as they are.'
            : 'Files are sent exactly as they are and may contain personal details.';
        }
      }
      role(node, 'replycancel').addEventListener('click', function () {
        if (state.editing) { ta.value = ''; }
        state.reply = null; state.editing = null; renderBars();
      });

      function addFiles(list) {
        Array.prototype.forEach.call(list, function (f) {
          if (state.files.length >= T.LIMITS.files) { say('At most ' + T.LIMITS.files + ' files per message.', true); return; }
          if (f.size > T.LIMITS.fileBytes) { say(F.safeName(f.name) + ' is larger than ' + (T.LIMITS.fileBytes / 1000000) + ' MB.', true); return; }
          state.files.push(f);
        });
        renderBars();
      }
      role(node, 'attach').addEventListener('click', function () { fileInput.click(); });
      fileInput.addEventListener('change', function () { addFiles(fileInput.files); fileInput.value = ''; });
      ta.addEventListener('paste', function (ev) { var fl = ev.clipboardData && ev.clipboardData.files; if (fl && fl.length) { ev.preventDefault(); addFiles(fl); } });
      node.addEventListener('dragover', function (ev) { if (ev.dataTransfer && Array.prototype.indexOf.call(ev.dataTransfer.types || [], 'Files') !== -1) { ev.preventDefault(); } });
      node.addEventListener('drop', function (ev) { if (ev.dataTransfer && ev.dataTransfer.files.length) { ev.preventDefault(); addFiles(ev.dataTransfer.files); } });
      ta.addEventListener('input', function () { ta.rows = Math.min(6, Math.max(1, ta.value.split('\n').length)); });
      ta.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing && !coarse()) { ev.preventDefault(); form.requestSubmit(); }
      });

      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        if (state.busy) { return; }
        var text = ta.value, editing = state.editing, reply = state.reply, files = state.files.slice();
        state.busy = true; sendBtn.disabled = true; say(files.length ? 'Encrypting and uploading...' : '');
        withKeyConfirm(role(node, 'keynote'), function (accept) {
          return editing ? T.edit(id, editing.id, text, { acceptKeyChange: accept })
            : T.sendText(id, text, { reply: reply && reply.id, files: files, acceptKeyChange: accept });
        }).then(function () {
          ta.value = ''; ta.rows = 1; state.reply = null; state.editing = null; state.files = []; renderBars(); say(''); toBottom();
        }).catch(fail).then(function () { state.busy = false; sendBtn.disabled = ta.disabled; if (!coarse()) { ta.focus(); } });
      });

      older.addEventListener('click', function () {
        var before = document.documentElement.scrollHeight;
        T.loadOlder(id).then(function () { renderLog(); window.scrollTo(0, window.scrollY + document.documentElement.scrollHeight - before); }).catch(fail);
      });

      // -- info panel
      var infoBtn = role(node, 'infobtn'), info = role(node, 'info');
      infoBtn.addEventListener('click', function () {
        state.infoOpen = !state.infoOpen; info.hidden = !state.infoOpen; infoBtn.setAttribute('aria-expanded', String(state.infoOpen));
        body.hidden = state.infoOpen; form.hidden = state.infoOpen;
        if (state.infoOpen) { renderInfo(); } else { renderLog(); toBottom(); }
      });
      function renderInfo() {
        var c = chat(); if (!c) { return; }
        clear(info);
        var p = clone('t-info'); info.appendChild(p);
        var isGroup = c.kind === 'group', admin = c.my_role === 'admin';
        role(p, 'memberhint').textContent = isGroup ? (admin ? 'You are an admin: you can add and remove people.' : 'Only admins can add or remove people.') : 'Compare key fingerprints with this person through another channel to be sure no one is in the middle.';
        var ul = role(p, 'members');
        c.members.forEach(function (m) {
          var li = el('li', 'member'), top = el('div', 'member-top');
          top.appendChild(el('strong', '', m.username + (m.username === M.state.username ? ' (you)' : '')));
          if (isGroup && m.role === 'admin') { top.appendChild(el('span', 'badge', 'admin')); }
          var key = el('button', 'linklike', 'Key fingerprint'); key.type = 'button';
          var out = el('p', 'hint'); out.hidden = true;
          key.addEventListener('click', function () {
            if (!out.hidden) { out.hidden = true; return; }
            M.fetchVerifiedKey(m.username, { readOnly: true }).then(function (k) {
              clear(out); out.hidden = false;
              out.appendChild(el('code', 'fpr', C.formatFingerprint(k.fingerprint)));
              out.appendChild(document.createTextNode(' ' + (k.verified ? 'You verified this key.' : k.changed ? 'This key changed since you first saw it.' : 'Not verified yet. ')));
              if (!k.verified && m.username !== M.state.username) {
                var mv = el('button', 'linklike', 'The fingerprints match'); mv.type = 'button';
                mv.addEventListener('click', function () { M.markVerified(m.username, k.fingerprint); say('Saved: you verified ' + m.username + '\'s key.'); out.hidden = true; });
                out.appendChild(mv);
              }
            }).catch(fail);
          });
          top.appendChild(key); li.appendChild(top); li.appendChild(out);
          if (isGroup && admin && m.username !== M.state.username) {
            var rm = el('button', 'linklike danger-text', 'Remove'); rm.type = 'button'; rm.setAttribute('aria-label', 'Remove ' + m.username);
            rm.addEventListener('click', function () {
              T.removeMember(id, m.username).then(function () { remember(); say(m.username + ' was removed. New messages will not be encrypted to them.'); renderInfo(); }).catch(fail);
            });
            top.appendChild(rm);
          }
          ul.appendChild(li);
        });
        var add = role(p, 'addform'); add.hidden = !(isGroup && admin);
        add.addEventListener('submit', function (ev) {
          ev.preventDefault(); var inp = $('input', add), who = names(inp.value); if (!who.length) { return; }
          withKeyConfirm(role(node, 'keynote'), function (accept) { return T.addMembers(id, who, { acceptKeyChange: accept }); })
            .then(function () { inp.value = ''; remember(); say('Added.'); renderInfo(); }).catch(fail);
        });
        var sel = role(p, 'ttl');
        T.TTL_LABELS.forEach(function (o) { var op = el('option', '', o[1]); op.value = String(o[0]); sel.appendChild(op); });
        sel.value = String(c.ttl_seconds || 0); sel.disabled = isGroup && !admin;
        sel.addEventListener('change', function () { T.setTtl(id, Number(sel.value)).then(function () { say(Number(sel.value) ? 'New messages will disappear after ' + T.ttlLabel(Number(sel.value)) + '.' : 'Disappearing messages are off.'); }).catch(fail); });
        var hide = role(p, 'hide'), leave = role(p, 'leave');
        hide.hidden = isGroup; leave.hidden = !isGroup;
        hide.addEventListener('click', function () { T.hide(id).then(function () { h.navigate('/chats'); }).catch(fail); });
        var armed = false;
        leave.addEventListener('click', function () {
          if (!armed) { armed = true; leave.textContent = 'Press again to leave'; return; }
          T.removeMember(id, M.state.username).then(function () { h.navigate('/chats'); }).catch(fail);
        });
      }

      // -- lifecycle
      var wasUnlocked = M.state.unlocked.length > 0;
      var offKey = M.onChange(function () {                      // unlocked or locked while this chat is open
        var now = M.state.unlocked.length > 0;
        if (now === wasUnlocked) { return; }
        wasUnlocked = now;
        if (now) { T.loadLatest(id).then(function () { update(); toBottom(); }).catch(fail); } else { update(); }
      });
      var onVisible = function () { if (!document.hidden) { maybeRead(); } };
      document.addEventListener('visibilitychange', onVisible);
      timers.expiry = setInterval(function () {
        if (!state.lastExpiring) { return; }
        var now = Date.now();
        if (Object.keys(state.bubbles).some(function (k) { return state.bubbles[k].expiresAt && state.bubbles[k].expiresAt <= now; })) { renderLog(); }
      }, 5000);

      function update() {
        if (!chat()) { return; }
        renderHeader(); checkMembers(); renderLog();
        if (state.infoOpen) { renderInfo(); }
      }
      renderHeader(); checkMembers(); renderBars();
      var loading = M.state.unlocked.length ? T.loadLatest(id).catch(fail) : Promise.resolve();
      loading.then(function () { renderLog(); toBottom(); });

      return {
        update: update,
        ready: function () { if (!coarse() && !ta.disabled) { setTimeout(function () { ta.focus(); }, 0); } },
        dispose: function () { offKey(); document.removeEventListener('visibilitychange', onVisible); clearInterval(timers.expiry); clearTimeout(timers.confirm); },
      };
    }

    // ---- new chat ------------------------------------------------------------------------------------------
    async function viewNewChat() {
      var node = clone('v-newchat');
      h.mountUnlock(role(node, 'unlock'));
      var box = role(node, 'keynote');
      role(node, 'direct').addEventListener('submit', h.guard(async function () {
        var u = $('#nc-user', node).value.trim().toLowerCase();
        if (!u) { throw new Error('Enter a username.'); }
        var c = await T.createDirect(u);
        h.navigate('/chats/' + c.id);
      }));
      role(node, 'group').addEventListener('submit', h.guard(async function () {
        var title = $('#nc-title', node).value, who = names($('#nc-members', node).value);
        if (!who.length) { throw new Error('Add at least one other person.'); }
        var c = await withKeyConfirm(box, function (accept) { return T.createGroup(title, who, { acceptKeyChange: accept }); });
        h.navigate('/chats/' + c.id);
      }));
      return { node: node, title: 'New chat' };
    }

    return [
      { re: /^\/chats$/, view: viewChats, auth: true },
      { re: /^\/chats\/new$/, view: viewNewChat, auth: true },
      { re: /^\/chats\/([0-9a-f-]{36})$/, view: viewChats, auth: true },
    ];
  } };
})();
