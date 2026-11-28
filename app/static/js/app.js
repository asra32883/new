/*
 * Tor-Mail single-page UI: client-side routing and all views.
 * Why a single page: the unlocked private key lives in memory only, so navigating with full page loads
 * would force the passphrase to be typed again on every click. The server serves the same shell for every
 * UI path, so reloads and direct links work (a reload locks the key, by design).
 *
 * Safety rules for this file: untrusted text (usernames, subjects, bodies) is only ever assigned with
 * textContent / value, never innerHTML; markup comes from the <template> elements in views.html.
 */
(function () {
  'use strict';
  var C = window.TorMailCrypto, M = window.TorMail, T = window.TorChat;

  // ---- helpers ------------------------------------------------------------------------------------------
  function $(sel, root) { return (root || document).querySelector(sel); }
  function role(node, name) { return node.querySelector('[data-role="' + name + '"]'); }
  function clone(id) { return document.getElementById(id).content.firstElementChild.cloneNode(true); }
  function clear(n) { while (n.firstChild) { n.removeChild(n.firstChild); } }
  function say(msg, isErr) { var s = $('#status'); s.textContent = msg || ''; s.className = msg ? (isErr ? 'err' : 'ok') : ''; }
  function errText(e) { return e && e.message ? e.message : 'Something went wrong.'; }
  function fmt(ts) { try { return new Date(ts).toLocaleString(); } catch (e) { return ''; } }
  function fmtSize(n) { return n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB'; }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) { n.className = cls; } if (text) { n.textContent = text; } return n; }
  function link(href, text) { var a = el('a', '', text); a.href = href; a.setAttribute('data-link', ''); return a; }
  function download(name, text) {
    var url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    var a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  var app = { keyInfo: undefined, sessionChecked: false, flash: null, rid: 0, cleanup: null };

  function flash(msg, isErr) { app.flash = { msg: msg, err: !!isErr }; }

  // ---- session + chrome -----------------------------------------------------------------------------------
  async function refreshKeyInfo() {
    app.keyInfo = M.state.username ? await M.getMyKey() : null;
    updateChrome();
  }

  async function checkSession() {
    if (app.sessionChecked) { return; }
    app.sessionChecked = true;
    try { await M.session(); await refreshKeyInfo(); } catch (e) { /* not signed in */ }
  }

  function sessionExpired() {
    M.state.username = null; M.state.csrf = null; M.lock(); app.keyInfo = null;
    flash('Your session has ended. Please sign in again.', true);
    navigate('/login?next=' + encodeURIComponent(location.pathname + location.search), true);
  }

  function updateChrome() {
    var signedIn = !!M.state.username;
    Array.prototype.forEach.call(document.querySelectorAll('[data-auth]'), function (n) {
      n.hidden = n.getAttribute('data-auth') === 'in' ? !signedIn : signedIn;
    });
    $('#who').textContent = signedIn ? '(' + M.state.username + ')' : '';
    var bar = $('#keybar'), st = $('#keystate');
    bar.hidden = !signedIn;
    if (signedIn && !app.chatOn) { app.chatOn = true; T.start(); }
    if (!signedIn && app.chatOn) { app.chatOn = false; T.stop(); }
    updateBadge();
    if (!signedIn) { return; }
    clear(st);
    // These words describe the real state of your key in this browser. They are not a claim about the connection.
    if (!app.keyInfo) {
      st.appendChild(document.createTextNode('Encryption key: not set up. '));
      st.appendChild(link('/keys', 'Create your key'));
    } else if (M.state.unlocked.length) {
      st.appendChild(document.createTextNode('Encryption key: unlocked in this browser.'));
    } else {
      st.appendChild(document.createTextNode('Encryption key: locked. '));
      if (M.localKeys(M.state.username).length) { st.appendChild(link('/keys', 'Unlock')); } else { st.appendChild(link('/keys', 'Import your key')); }
    }
  }
  M.onChange(updateChrome);
  function updateBadge() {
    var b = $('#chat-badge'), n = M.state.username ? T.unreadTotal() : 0;
    if (!b) { return; }
    b.hidden = !n; b.textContent = n > 99 ? '99+' : String(n);
    b.setAttribute('aria-label', n + ' chats with unread messages');
  }
  T.onChange(function (type) { if (type === 'signedout') { sessionExpired(); } else if (type === 'chats') { updateBadge(); } });

  function onError(e) {
    if (e && e.status === 401) { sessionExpired(); return; }
    say(errText(e), true);
  }
  // wraps an event handler: prevents default, catches errors, shows them in the status line
  function guard(fn) {
    return function (ev) {
      if (ev && ev.preventDefault) { ev.preventDefault(); }
      return Promise.resolve().then(function () { return fn(ev); }).catch(onError);
    };
  }

  // Unlock panel used by views that need the key. Shows nothing when already unlocked.
  function mountUnlock(container, onDone) {
    clear(container);
    if (M.state.unlocked.length) { return; }
    if (!M.localKeys(M.state.username).length) {
      var box = el('div', 'notice');
      box.appendChild(document.createTextNode('This browser does not hold your encryption key, so messages cannot be read or sent here. '));
      box.appendChild(link('/keys', app.keyInfo ? 'Import your key backup' : 'Create your key'));
      box.appendChild(document.createTextNode('.'));
      container.appendChild(box);
      return;
    }
    var form = clone('t-unlock');
    form.addEventListener('submit', guard(async function () {
      var input = $('#unlock-pass-inline', form);
      await M.unlockLocal(input.value);
      input.value = '';
      clear(container); say('Unlocked.');
      if (onDone) { await onDone(); }
    }));
    container.appendChild(form); addPasswordToggles(form.parentNode);
  }

  // ---- router -----------------------------------------------------------------------------------------------
  var routes = [
    { re: /^\/$/, view: viewWelcome, auth: null },
    { re: /^\/register$/, view: viewRegister, auth: false },
    { re: /^\/login$/, view: viewLogin, auth: false },
    { re: /^\/(inbox|sent|trash)$/, view: viewMailbox, auth: true },
    { re: /^\/compose$/, view: viewCompose, auth: true },
    { re: /^\/message\/(inbox|sent|trash)\/([0-9a-f-]{36})$/, view: viewMessage, auth: true },
    { re: /^\/settings$/, view: viewSettings, auth: true },
    { re: /^\/keys$/, view: viewKeys, auth: true },
    { re: /^\/privacy$/, view: viewPrivacy, auth: null },
  ];

  var helpers = { $: $, role: role, clone: clone, clear: clear, el: el, say: say, fmt: fmt, fmtSize: fmtSize, guard: guard,
    mountUnlock: mountUnlock, navigate: function (p, r) { return navigate(p, r); }, onError: function (e) { return onError(e); } };
  routes = routes.concat(window.TorChatUI.install(helpers));

  function match(path) {
    for (var i = 0; i < routes.length; i++) {
      var m = path.match(routes[i].re);
      if (m) { return { route: routes[i], args: m.slice(1) }; }
    }
    return null;
  }

  function safeNext(n) {
    return typeof n === 'string' && n.charAt(0) === '/' && n.charAt(1) !== '/' && n.length < 300 && !!match(n.split('?')[0]) ? n : null;
  }

  async function navigate(url, replace) {
    history[replace ? 'replaceState' : 'pushState'](null, '', url);
    return render();
  }

  // Marks the nav link for the current page (screen readers and a visual highlight).
  function markCurrentNav() {
    Array.prototype.forEach.call(document.querySelectorAll('#nav a'), function (a) {
      var here = a.getAttribute('href') === location.pathname || (a.getAttribute('href') === '/inbox' && location.pathname.indexOf('/message/inbox') === 0)
        || (a.getAttribute('href') === '/sent' && location.pathname.indexOf('/message/sent') === 0);
      if (here) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); }
    });
  }

  // One "Show password" checkbox per form that has password fields. Typing a password blind on a phone is the
  // most common cause of failed sign-ups, and the field is never shown unless the person asks.
  var toggleSeq = 0;
  function addPasswordToggles(root) {
    Array.prototype.forEach.call(root.querySelectorAll('form'), function (form) {
      var fields = form.querySelectorAll('input[type=password]');
      if (!fields.length || form.querySelector('[data-role=showpw]')) { return; }
      var id = 'showpw-' + (++toggleSeq), label = document.createElement('label'), box = document.createElement('input');
      label.className = 'check'; label.setAttribute('for', id); label.setAttribute('data-role', 'showpw');
      box.type = 'checkbox'; box.id = id;
      label.appendChild(box); label.appendChild(document.createTextNode('Show password' + (fields.length > 1 ? 's' : '')));
      box.addEventListener('change', function () {
        Array.prototype.forEach.call(fields, function (f) { f.type = box.checked ? 'text' : 'password'; });
      });
      fields[fields.length - 1].insertAdjacentElement('afterend', label);
      // keep hints that belong to the last field above the toggle
      var next = label.nextElementSibling;
      while (next && next.classList.contains('hint')) { var h = next; next = next.nextElementSibling; label.insertAdjacentElement('beforebegin', h); }
    });
  }

  async function render() {
    var id = ++app.rid;
    if (app.cleanup) { try { app.cleanup(); } catch (e) { /* ignore */ } app.cleanup = null; }
    await checkSession();
    if (id !== app.rid) { return; }
    var found = match(location.pathname);
    var view;
    if (!found) {
      view = { node: clone('v-404'), title: 'Page not found' };
    } else if (found.route.auth === true && !M.state.username) {
      return navigate('/login?next=' + encodeURIComponent(location.pathname + location.search), true);
    } else if (found.route.auth === false && M.state.username) {
      return navigate('/inbox', true);
    } else {
      try { view = await found.route.view(found.args); } catch (e) {
        if (e && e.status === 401) { return sessionExpired(); }
        view = { node: el('p', 'notice warn', 'This page could not be loaded: ' + errText(e)), title: 'Error' };
      }
    }
    if (id !== app.rid) { return; }
    var root = $('#view');
    clear(root); root.appendChild(view.node);
    app.cleanup = view.cleanup || null;
    document.title = view.title + ' - Tor-Mail';
    if (app.flash) { say(app.flash.msg, app.flash.err); app.flash = null; } else { say(''); }
    updateChrome();
    addPasswordToggles(root);
    markCurrentNav();
    var h1 = $('h1', root);
    if (h1) { h1.focus(); }
    window.scrollTo(0, 0);
    if (view.after) { view.after(); }
  }

  document.addEventListener('click', function (ev) {
    var a = ev.target.closest && ev.target.closest('a[data-link]');
    if (!a || ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) { return; }
    ev.preventDefault();
    navigate(a.getAttribute('href'));
  });
  window.addEventListener('popstate', render);
  $('#logout').addEventListener('click', guard(async function () {
    try { await M.logout(); } catch (e) { /* already signed out */ }
    app.keyInfo = null; flash('You have been signed out.'); await navigate('/');
  }));

  // ---- welcome / privacy ----------------------------------------------------------------------------------------
  function viewWelcome() {
    var node = clone('v-welcome');
    role(node, 'example').textContent = 'username@' + location.hostname;
    return { node: node, title: 'Welcome' };
  }
  function viewPrivacy() { return { node: clone('v-privacy'), title: 'Privacy policy' }; }

  // ---- register / login --------------------------------------------------------------------------------------------
  function viewRegister() {
    var node = clone('v-register'), form = role(node, 'form');
    form.addEventListener('submit', guard(async function () {
      var u = $('#reg-user', node).value.trim(), p = $('#reg-pass', node).value, p2 = $('#reg-pass2', node).value;
      if (p !== p2) { throw new Error('The passwords do not match.'); }
      if (p.length < 12) { throw new Error('Use a password of at least 12 characters.'); }
      var btn = role(node, 'submit'), work = role(node, 'work');
      btn.disabled = true; work.hidden = false; say('');
      try {
        await M.register(u, p);
      } finally { btn.disabled = false; work.hidden = true; }
      await refreshKeyInfo();
      flash('Account created. Next step: create your encryption key.');
      await navigate('/keys');
    }));
    return { node: node, title: 'Create an account' };
  }

  function viewLogin() {
    var node = clone('v-login'), form = role(node, 'form');
    form.addEventListener('submit', guard(async function () {
      await M.login($('#login-user', node).value.trim(), $('#login-pass', node).value);
      await refreshKeyInfo();
      var next = safeNext(new URLSearchParams(location.search).get('next'));
      if (!app.keyInfo) { flash('You have not created an encryption key yet.'); return navigate('/keys'); }
      return navigate(next || '/inbox');
    }));
    return { node: node, title: 'Sign in' };
  }

  // ---- mailbox ---------------------------------------------------------------------------------------------------------
  var FOLDER_TITLE = { inbox: 'Inbox', sent: 'Sent', trash: 'Trash' };

  function viewMailbox(args) {
    var folder = args[0], node = clone('v-mailbox');
    role(node, 'title').textContent = FOLDER_TITLE[folder];
    var listEl = role(node, 'list'), countEl = role(node, 'count'), emptyEl = role(node, 'empty'), moreBtn = role(node, 'more');
    var items = [], nodes = {}, cursor = null, loaded = false, query = '', unread = null, dead = false, decrypting = false;

    function matches(it, q) {
      var v = it.view, raw = it.raw;
      var hay = [raw.sender || '', (raw.recipients || []).join(' '), v ? v.subject + ' ' + v.body + ' ' + v.to.join(' ') : ''].join('\n').toLowerCase();
      return hay.indexOf(q) !== -1;
    }

    function fill(li, it) {
      var raw = it.raw, v = it.view;
      var subject = v ? (v.subject || '(no subject)') : it.error ? '(cannot decrypt)' : M.state.unlocked.length ? '(decrypting...)' : '(locked: unlock to read)';
      var a = role(li, 'subject').parentNode;
      role(li, 'subject').textContent = subject;
      a.setAttribute('href', '/message/' + folder + '/' + raw.id);
      var who = folder === 'sent' ? 'To ' + ((v ? v.to : raw.recipients).join(', ') || '(no recipients left)')
        : 'From ' + (raw.sender || '(deleted account)');
      var when = fmt(raw.delivered_at || raw.created_at);
      role(li, 'meta').textContent = who + ' · ' + when + ' · ' + fmtSize(raw.size_bytes);
      var isUnread = folder === 'inbox' && !raw.is_read;
      li.classList.toggle('is-unread', isUnread);
      role(li, 'unread').hidden = !isUnread;
    }

    function refresh() {
      var q = query.trim().toLowerCase(), shown = 0;
      items.forEach(function (it) {
        var li = nodes[it.raw.id];
        if (!li) { return; }
        fill(li, it);
        var ok = !q || matches(it, q);
        li.hidden = !ok;
        if (ok) { shown++; }
      });
      var extra = unread !== null ? ' (' + unread + ' unread)' : '';
      countEl.textContent = loaded ? (q ? shown + ' of ' + items.length + ' loaded messages match' : items.length + ' message' + (items.length === 1 ? '' : 's') + ' loaded' + extra) : 'Loading...';
      emptyEl.hidden = !(loaded && items.length === 0);
      moreBtn.hidden = !cursor;
    }

    function addItem(raw) {
      var it = { raw: raw, view: null, error: false }, li = clone('t-msgitem');
      items.push(it); nodes[raw.id] = li; listEl.appendChild(li);
      var del = li.querySelector('[data-act="delete"]'), res = li.querySelector('[data-act="restore"]');
      del.textContent = folder === 'trash' ? 'Delete permanently' : (folder === 'inbox' ? 'Move to Trash' : 'Delete');
      res.hidden = folder !== 'trash';
      del.addEventListener('click', guard(async function () {
        if (folder !== 'inbox' && !window.confirm('Delete this message permanently? This cannot be undone.')) { return; }
        var r = await M.del(folder, raw.id);
        items.splice(items.indexOf(it), 1); listEl.removeChild(li); delete nodes[raw.id];
        say(r.result === 'trashed' ? 'Moved to Trash. It is deleted permanently after the retention period.' : 'Deleted.');
        refresh();
      }));
      res.addEventListener('click', guard(async function () {
        await M.request('POST', '/api/mailbox/trash/' + raw.id + '/restore');
        items.splice(items.indexOf(it), 1); listEl.removeChild(li); delete nodes[raw.id];
        say('Restored to your inbox.'); refresh();
      }));
    }

    async function decryptPending() {
      if (decrypting || !M.state.unlocked.length) { return; }
      decrypting = true;
      try {
        for (var i = 0; i < items.length && !dead; i++) {
          var it = items[i];
          if (it.view || it.error) { continue; }
          try { it.view = await M.open(it.raw, folder); } catch (e) { it.error = true; }
          if (i % 5 === 4) { refresh(); }
        }
      } finally { decrypting = false; refresh(); }
    }

    async function load() {
      var page = await M.list(folder, cursor, 25);
      page.items.forEach(addItem);
      cursor = page.next_cursor; loaded = true;
      if (typeof page.unread === 'number') { unread = page.unread; }
      refresh();
      await decryptPending();
    }

    mountUnlock(role(node, 'unlock'), decryptPending);
    role(node, 'searchform').addEventListener('submit', function (ev) { ev.preventDefault(); });
    $('#search', node).addEventListener('input', function (ev) { query = ev.target.value; refresh(); });
    moreBtn.addEventListener('click', guard(load));
    load().catch(function (e) { if (!dead) { onError(e); } });
    return { node: node, title: FOLDER_TITLE[folder], cleanup: function () { dead = true; } };
  }

  // ---- compose -------------------------------------------------------------------------------------------------------------
  var NAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;

  function viewCompose() {
    var node = clone('v-compose'), form = role(node, 'form');
    var to = $('#compose-to', node), subj = $('#compose-subject', node), body = $('#compose-body', node);
    var params = new URLSearchParams(location.search);
    to.value = (params.get('to') || '').slice(0, 200); subj.value = (params.get('subject') || '').slice(0, 300);
    role(node, 'nokey').hidden = !!app.keyInfo;
    mountUnlock(role(node, 'unlock'));
    var changed = [];       // recipients whose key changed since you last wrote to them
    form.addEventListener('submit', guard(async function () {
      if (!M.state.unlocked.length) { throw new Error('Unlock your key first (see the box above).'); }
      var seen = {}, names = to.value.split(/[\s,;]+/).map(function (s) { return s.toLowerCase(); }).filter(function (s) {
        if (!s || seen[s]) { return false; } seen[s] = 1; return true;
      });
      if (!names.length) { throw new Error('Enter at least one recipient.'); }
      var bad = names.filter(function (n) { return !NAME_RE.test(n); });
      if (bad.length) { throw new Error('Not a valid username: ' + bad[0]); }
      if (!body.value.trim()) { throw new Error('The message is empty.'); }
      var accept = role(node, 'keychange-ok').checked ? changed.slice() : [];
      var btn = role(node, 'send');
      btn.disabled = true; say('Encrypting and sending...');
      try {
        var res = await M.send(names, subj.value, body.value, { acceptKeyChange: accept });
        to.value = ''; subj.value = ''; body.value = '';
        role(node, 'keychange').hidden = true; role(node, 'keychange-ok').checked = false; changed = [];
        say('Delivered to ' + res.delivered_to.join(', ') + '. The subject and text were encrypted in your browser first.');
      } catch (e) {
        if (e && e.name === 'KeyChangedError') {
          changed.push(e.username);
          role(node, 'keychange-text').textContent = 'The encryption key for ' + e.username + ' has changed since you last wrote to them. ' +
            'Old fingerprint: ' + C.formatFingerprint(e.oldFingerprint) + '. New fingerprint: ' + C.formatFingerprint(e.newFingerprint) + '. ' +
            'This is normal if they created a new key, but it is also what a key substitution by the server would look like.';
          role(node, 'keychange').hidden = false;
          throw new Error('Review the key change below, then send again.');
        }
        throw e;
      } finally { btn.disabled = false; }
    }));
    return { node: node, title: 'New message' };
  }

  // ---- read a message ----------------------------------------------------------------------------------------------------
  function viewMessage(args) {
    var folder = args[0], id = args[1], node = clone('v-message');
    var trust = role(node, 'trust'), raw = null;

    function line(kind, strong, text) {
      var li = el('li', kind); li.appendChild(el('strong', '', strong)); li.appendChild(document.createTextNode(text)); trust.appendChild(li);
    }

    function renderOpened(v) {
      clear(trust);
      role(node, 'subject').textContent = v.subject || '(no subject)';
      role(node, 'from').textContent = v.from + (v.senderMismatch ? ' (as written inside the message; the server delivered it from ' + (raw.sender || 'unknown') + ')' : '');
      role(node, 'to').textContent = v.to.join(', ');
      role(node, 'written').textContent = fmt(v.sentAt) + ' (the sender\'s clock, inside the signed message)';
      role(node, 'body').textContent = v.body;
      line('good', 'Decrypted in your browser. ', 'The server only holds the encrypted form.');
      var who = folder === 'sent' ? 'you' : v.from;
      if (v.senderMismatch) { line('bad', 'Sender mismatch. ', 'The server says this came from ' + (raw.sender || 'an unknown account') + ' but the signed contents say ' + v.from + '. Do not trust it.'); }
      if (v.signature === 'valid') {
        line('good', 'Signature valid. ', 'Signed by the key ' + who + ' currently has on the server.');
        if (v.senderKeyVerified) { line('good', 'Key verified. ', 'You confirmed this key\'s fingerprint yourself.'); }
        else if (folder !== 'sent') { line('warn', 'Key not verified. ', 'Whoever controls the server could substitute keys. Compare fingerprints below to be sure.'); }
      } else if (v.signature === 'invalid') {
        line('bad', 'Signature invalid. ', 'This was not signed by ' + who + '\'s current key. Do not trust who it is from.');
      } else if (v.signature === 'unsigned') {
        line('bad', 'Not signed. ', 'The sender cannot be confirmed.');
      } else {
        line('warn', 'Signature not checked. ', 'The sender\'s key is unavailable (the account may have been deleted).');
      }
      if (v.senderKeyChanged) { line('warn', 'Key changed. ', v.from + '\'s key is different from the one you saved earlier.'); }
      var box = role(node, 'verify');
      box.hidden = !(folder !== 'sent' && v.senderFingerprint && !v.senderKeyVerified && !v.senderMismatch);
      if (!box.hidden) {
        role(node, 'fpr').textContent = C.formatFingerprint(v.senderFingerprint);
        role(node, 'markverified').onclick = guard(async function () {
          M.markVerified(raw.sender, v.senderFingerprint);
          renderOpened(await M.open(raw, folder)); say('Saved: you verified ' + raw.sender + '\'s key.');
        });
      }
      var reply = role(node, 'reply');
      reply.hidden = folder === 'sent' || !raw.sender;
      if (!reply.hidden) {
        var subject = /^re:/i.test(v.subject) ? v.subject : 'Re: ' + v.subject;
        reply.setAttribute('href', '/compose?to=' + encodeURIComponent(raw.sender) + '&subject=' + encodeURIComponent(subject.slice(0, 300)));
      }
    }

    async function decryptAndShow() {
      var v;
      try { v = await M.open(raw, folder); } catch (e) {
        role(node, 'subject').textContent = '(cannot decrypt)';
        say('This message cannot be decrypted with the keys in this browser. It may have been encrypted to an older key: import that key\'s backup on the Keys page.', true);
        return;
      }
      renderOpened(v);
      if (folder === 'inbox' && !raw.is_read) { raw.is_read = true; M.setRead(id, true).then(updateChrome, function () { /* non-fatal */ }); }
    }

    async function init() {
      raw = await M.request('GET', '/api/mailbox/' + folder + '/' + id);
      role(node, 'subject').textContent = M.state.unlocked.length ? '' : '(locked)';
      role(node, 'from').textContent = folder === 'sent' ? M.state.username : (raw.sender || '(deleted account)');
      role(node, 'to').textContent = folder === 'sent' ? (raw.recipients || []).join(', ') : M.state.username;
      role(node, 'written').textContent = '(unlock to see)';
      role(node, 'delivered').textContent = fmt(raw.delivered_at || raw.created_at);
      mountUnlock(role(node, 'unlock'), decryptAndShow);
      if (M.state.unlocked.length) { await decryptAndShow(); }
    }

    var del = role(node, 'delete'), restore = role(node, 'restore');
    del.textContent = folder === 'trash' ? 'Delete permanently' : (folder === 'inbox' ? 'Move to Trash' : 'Delete');
    restore.hidden = folder !== 'trash';
    del.addEventListener('click', guard(async function () {
      if (folder !== 'inbox' && !window.confirm('Delete this message permanently? This cannot be undone.')) { return; }
      var r = await M.del(folder, id);
      flash(r.result === 'trashed' ? 'Moved to Trash.' : 'Deleted.'); await navigate('/' + folder);
    }));
    restore.addEventListener('click', guard(async function () {
      await M.request('POST', '/api/mailbox/trash/' + id + '/restore'); flash('Restored to your inbox.'); await navigate('/inbox');
    }));
    return init().then(function () { return { node: node, title: 'Message' }; });
  }

  // ---- settings --------------------------------------------------------------------------------------------------------------
  function viewSettings() {
    var node = clone('v-settings');
    role(node, 'address').textContent = M.state.username + '@' + location.hostname;

    function lockState() {
      role(node, 'lockstate').textContent = M.state.unlocked.length ? 'Your key is unlocked in this browser.' : 'Your key is locked.';
      role(node, 'lock').hidden = !M.state.unlocked.length;
    }
    lockState();
    role(node, 'lock').addEventListener('click', function () { M.lock(); lockState(); say('Key locked.'); });
    var rc = role(node, 'receipts'); rc.checked = T.prefs().receipts;
    rc.addEventListener('change', function () { T.setPref('receipts', rc.checked); say(rc.checked ? 'Read receipts are on.' : 'Read receipts are off.'); });

    role(node, 'pwform').addEventListener('submit', guard(async function () {
      var cur = $('#pw-current', node), n1 = $('#pw-new', node), n2 = $('#pw-new2', node);
      if (n1.value !== n2.value) { throw new Error('The new passwords do not match.'); }
      if (n1.value.length < 12) { throw new Error('Use a password of at least 12 characters.'); }
      await M.request('POST', '/api/account/password', { current_password: cur.value, new_password: n1.value });
      cur.value = n1.value = n2.value = '';
      say('Password changed. Your other sessions were signed out.'); await loadSessions();
    }));

    var sessEl = role(node, 'sessions');
    async function loadSessions() {
      var list = await M.request('GET', '/api/account/sessions');
      clear(sessEl);
      list.forEach(function (s) {
        var li = clone('t-session');
        role(li, 'info').textContent = 'Started ' + fmt(s.created_at) + ', last active ' + fmt(s.last_seen_at) + (s.current ? ' (this session)' : '');
        var btn = role(li, 'revoke');
        btn.hidden = s.current;
        btn.addEventListener('click', guard(async function () {
          await M.request('DELETE', '/api/account/sessions/' + s.id); say('That session was signed out.'); await loadSessions();
        }));
        sessEl.appendChild(li);
      });
    }
    role(node, 'logout-all').addEventListener('click', guard(async function () {
      await M.request('POST', '/api/auth/logout-all');
      M.state.username = null; M.state.csrf = null; M.lock(); app.keyInfo = null;
      flash('You were signed out of every session.'); await navigate('/');
    }));

    role(node, 'delform').addEventListener('submit', guard(async function () {
      var pw = $('#del-pass', node);
      if (!$('#del-ack', node).checked) { throw new Error('Tick the box to confirm.'); }
      var name = M.state.username, wipe = $('#del-wipe', node).checked;
      await M.request('POST', '/api/account/delete', { password: pw.value });
      if (wipe) { M.forgetLocalData(name); }
      M.state.username = null; M.state.csrf = null; M.lock(); app.keyInfo = null;
      flash('Your account was deleted.'); await navigate('/');
    }));

    return loadSessions().then(function () { return { node: node, title: 'Settings' }; });
  }

  // ---- encryption keys -------------------------------------------------------------------------------------------------------
  function viewKeys() {
    var node = clone('v-keys');
    function q(id) { return node.querySelector('#' + id); }
    function show(id, on) { q(id).hidden = !on; }
    var server = null;

    async function localKeyFor(fpr) {
      var list = M.localKeys(M.state.username);
      for (var i = 0; i < list.length; i++) { if ((await C.privateFingerprint(list[i])) === fpr) { return list[i]; } }
      return null;
    }

    async function refresh() {
      await refreshKeyInfo();
      server = app.keyInfo;
      var haveLocal = server ? await localKeyFor(server.fingerprint) : null;
      q('fingerprint').textContent = server ? C.formatFingerprint(server.fingerprint) : 'none yet';
      q('local-state').textContent = !server ? 'No key has been created for this account.'
        : haveLocal ? 'This browser holds your private key (passphrase-protected).'
        : 'This browser does not hold the private key for your current key. Import your backup to read or send mail here.';
      q('unlock-state').textContent = M.state.unlocked.length ? 'Unlocked for this session.' : 'Locked.';
      show('s-create', true);
      q('h-create').textContent = server ? 'Create a new key (rotate)' : 'Create your encryption key';
      q('create-btn').textContent = server ? 'Replace my key' : 'Create key';
      show('rotate-warning', !!server);
      show('s-unlock', !!haveLocal && !M.state.unlocked.length);
      show('s-export', !!server);
      q('dl-backup').hidden = !haveLocal;
      show('s-import', !!server);
      show('s-sync', !!server);
      if (server) {
        q('sync-state').textContent = server.has_server_backup ? 'An encrypted backup is stored on the server.' : 'No backup is stored on the server.';
        show('f-sync-on', !server.has_server_backup && !!haveLocal);
        show('sync-off', server.has_server_backup);
        show('sync-restore', server.has_server_backup && !haveLocal);
      }
    }

    q('f-create').addEventListener('submit', guard(async function () {
      var p1 = q('create-pass').value, p2 = q('create-pass2').value;
      if (p1 !== p2) { throw new Error('The passphrases do not match.'); }
      var chk = C.checkPassphrase(p1);
      if (!chk.ok) { throw new Error(chk.reason); }
      say('Generating key...');
      var k = await C.generateKey(M.state.username, p1);
      if (!(await C.isPassphraseProtected(k.privateKey))) { throw new Error('Internal error: key is not protected. Nothing was saved.'); }
      if (!(await M.addLocalKey(M.state.username, k.privateKey))) { throw new Error('This browser cannot store the key (storage disabled?). Nothing was uploaded.'); }
      await M.putMyKey(k.publicKey, k.fingerprint, null);      // public key only; the private key never leaves the browser
      download('tormail-private-key-backup-' + k.fingerprint.slice(-8) + '.asc', k.privateKey);
      await M.unlockLocal(p1);
      q('create-pass').value = ''; q('create-pass2').value = ''; q('create-ack').checked = false;
      await refresh();
      say('Key created (' + k.kdf + '). A backup file was downloaded: keep it safe, it is the only way to recover your key.');
    }));

    q('f-unlock').addEventListener('submit', guard(async function () {
      await M.unlockLocal(q('unlock-pass').value);
      q('unlock-pass').value = '';
      await refresh(); say('Unlocked.');
    }));

    q('dl-public').addEventListener('click', function () {
      if (server) { download('tormail-public-key-' + server.fingerprint.slice(-8) + '.asc', server.public_key); }
    });
    q('dl-backup').addEventListener('click', guard(async function () {
      var k = await localKeyFor(server.fingerprint);
      if (!k) { throw new Error('No private key for the current key in this browser.'); }
      download('tormail-private-key-backup-' + server.fingerprint.slice(-8) + '.asc', k);
    }));

    q('f-import').addEventListener('submit', guard(async function () {
      var file = q('import-file').files[0];
      if (!file || file.size > 100000) { throw new Error('Choose a key backup file (under 100 KB).'); }
      var armored = (await file.text()).trim();
      if (!(await C.isPassphraseProtected(armored))) { throw new Error('That key is not passphrase-protected, so it was not imported.'); }
      await C.unlock([armored], q('import-pass').value);   // proves the passphrase opens it
      if (!(await M.addLocalKey(M.state.username, armored))) { throw new Error('This browser cannot store the key.'); }
      var fpr = await C.privateFingerprint(armored);
      q('import-pass').value = ''; q('import-file').value = '';
      await refresh();
      say(server && fpr === server.fingerprint ? 'Backup imported. It matches your current key.'
        : 'Backup imported, but it is NOT your account\'s current key. It can open old mail only.');
    }));

    q('f-sync-on').addEventListener('submit', guard(async function () {
      var k = await localKeyFor(server.fingerprint);
      if (!k) { throw new Error('This browser does not hold your current private key.'); }
      await M.putMyKey(server.public_key, server.fingerprint, k);
      q('sync-ack').checked = false;
      await refresh(); say('Encrypted backup stored on the server.');
    }));
    q('sync-off').addEventListener('click', guard(async function () { await M.deleteServerBackup(); await refresh(); say('Server backup removed.'); }));
    q('sync-restore').addEventListener('click', guard(async function () {
      var armored = await M.fetchServerBackup();
      if (!(await C.isPassphraseProtected(armored))) { throw new Error('The stored backup is not passphrase-protected and was ignored.'); }
      await M.addLocalKey(M.state.username, armored);
      await refresh(); say('Backup restored into this browser. Enter your passphrase to unlock it.');
    }));

    return refresh().then(function () { return { node: node, title: 'Encryption keys' }; });
  }

  // Auto-lock: an unlocked key left in a forgotten tab is a risk. After 15 idle minutes the key is dropped from memory
  // and the current view is rebuilt, so decrypted text disappears from the page too.
  var LOCK_AFTER_MS = 15 * 60 * 1000, lastActive = Date.now();
  ['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(function (n) {
    document.addEventListener(n, function () { lastActive = Date.now(); }, { passive: true, capture: true });
  });
  setInterval(function () {
    if (M.state.unlocked.length && Date.now() - lastActive > LOCK_AFTER_MS) {
      M.lock(); app.flash = { msg: 'Your key was locked after 15 minutes without activity.', err: false }; render();
    }
  }, 20000);

  render();
})();
