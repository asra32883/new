/* Key management page. Uses textContent only (never innerHTML) for anything that came from outside. */
(function () {
  'use strict';
  var C = window.TorMailCrypto, M = window.TorMail;
  function $(id) { return document.getElementById(id); }
  function show(id, on) { $(id).hidden = !on; }
  function say(msg, isErr) { var s = $('status'); s.textContent = msg; s.className = isErr ? 'err' : 'ok'; }

  function download(name, text) {
    var url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    var a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  var server = null;

  async function localKeyFor(fpr) {
    var list = M.localKeys(M.state.username);
    for (var i = 0; i < list.length; i++) { if ((await C.privateFingerprint(list[i])) === fpr) { return list[i]; } }
    return null;
  }

  async function refresh() {
    try { await M.session(); } catch (e) { show('s-signin', true); show('keys-ui', false); return; }
    show('s-signin', false); show('keys-ui', true);
    server = await M.getMyKey();
    var haveLocal = server ? await localKeyFor(server.fingerprint) : null;
    $('fingerprint').textContent = server ? C.formatFingerprint(server.fingerprint) : 'none yet';
    $('local-state').textContent = !server ? 'No key has been created for this account.'
      : haveLocal ? 'This browser holds your private key (passphrase-protected).'
      : 'This browser does not hold the private key for your current key. Import your backup to read or send mail here.';
    $('unlock-state').textContent = M.state.unlocked.length ? 'Unlocked for this session.' : 'Locked.';
    show('s-create', true);
    $('h-create').textContent = server ? 'Create a new key (rotate)' : 'Create your encryption key';
    $('create-btn').textContent = server ? 'Replace my key' : 'Create key';
    show('rotate-warning', !!server);
    show('s-unlock', !!haveLocal && !M.state.unlocked.length);
    show('s-export', !!server);
    $('dl-backup').hidden = !haveLocal;
    show('s-import', !!server);
    show('s-sync', !!server);
    if (server) {
      $('sync-state').textContent = server.has_server_backup ? 'An encrypted backup is stored on the server.' : 'No backup is stored on the server.';
      show('f-sync-on', !server.has_server_backup && !!haveLocal);
      show('sync-off', server.has_server_backup);
      show('sync-restore', server.has_server_backup && !haveLocal);
    }
  }

  async function guard(fn) {
    try { await fn(); } catch (e) { say(e && e.message ? e.message : 'Something went wrong', true); }
  }

  $('f-create').addEventListener('submit', function (ev) {
    ev.preventDefault();
    guard(async function () {
      var p1 = $('create-pass').value, p2 = $('create-pass2').value;
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
      $('create-pass').value = ''; $('create-pass2').value = ''; $('create-ack').checked = false;
      await refresh();
      say('Key created (' + k.kdf + '). A backup file was downloaded: keep it safe, it is the only way to recover your key.');
    });
  });

  $('f-unlock').addEventListener('submit', function (ev) {
    ev.preventDefault();
    guard(async function () {
      await M.unlockLocal($('unlock-pass').value);
      $('unlock-pass').value = '';
      await refresh(); say('Unlocked.');
    });
  });

  $('dl-public').addEventListener('click', function () {
    if (server) { download('tormail-public-key-' + server.fingerprint.slice(-8) + '.asc', server.public_key); }
  });
  $('dl-backup').addEventListener('click', function () {
    guard(async function () {
      var k = await localKeyFor(server.fingerprint);
      if (!k) { throw new Error('No private key for the current key in this browser.'); }
      download('tormail-private-key-backup-' + server.fingerprint.slice(-8) + '.asc', k);
    });
  });

  $('f-import').addEventListener('submit', function (ev) {
    ev.preventDefault();
    guard(async function () {
      var file = $('import-file').files[0];
      if (!file || file.size > 100000) { throw new Error('Choose a key backup file (under 100 KB).'); }
      var armored = (await file.text()).trim();
      if (!(await C.isPassphraseProtected(armored))) { throw new Error('That key is not passphrase-protected, so it was not imported.'); }
      await C.unlock([armored], $('import-pass').value);   // proves the passphrase opens it
      if (!(await M.addLocalKey(M.state.username, armored))) { throw new Error('This browser cannot store the key.'); }
      var fpr = await C.privateFingerprint(armored);
      $('import-pass').value = ''; $('import-file').value = '';
      await refresh();
      say(server && fpr === server.fingerprint ? 'Backup imported. It matches your current key.'
        : 'Backup imported, but it is NOT your account\'s current key. It can open old mail only.');
    });
  });

  $('f-sync-on').addEventListener('submit', function (ev) {
    ev.preventDefault();
    guard(async function () {
      var k = await localKeyFor(server.fingerprint);
      if (!k) { throw new Error('This browser does not hold your current private key.'); }
      await M.putMyKey(server.public_key, server.fingerprint, k);
      $('sync-ack').checked = false;
      await refresh(); say('Encrypted backup stored on the server.');
    });
  });
  $('sync-off').addEventListener('click', function () {
    guard(async function () { await M.deleteServerBackup(); await refresh(); say('Server backup removed.'); });
  });
  $('sync-restore').addEventListener('click', function () {
    guard(async function () {
      var armored = await M.fetchServerBackup();
      if (!(await C.isPassphraseProtected(armored))) { throw new Error('The stored backup is not passphrase-protected and was ignored.'); }
      await M.addLocalKey(M.state.username, armored);
      await refresh(); say('Backup restored into this browser. Enter your passphrase to unlock it.');
    });
  });

  refresh();
})();
