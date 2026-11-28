"""End-to-end encryption tests run in real Chromium against the real app under its real CSP."""
import re
import sqlite3
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

LOGIN_PW = "login password 12345"
PASS = {"alice": "alice key passphrase one", "bobby": "bobby key passphrase two", "mallory": "mallory key passphrase 3",
        "carol": "carol key passphrase four"}


def wait(page, expr, timeout=30000):
    """Poll a JS expression. page.wait_for_function evals strings, which the app's CSP (correctly) forbids."""
    import time
    deadline = time.time() + timeout / 1000
    while time.time() < deadline:
        if page.evaluate(f"() => !!({expr})"):
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for: {expr}")


class Session:
    """One browser context (= one person's browser profile) with request/console auditing."""

    def __init__(self, browser, base, name, audit):
        self.base, self.name = base, name
        self.ctx = browser.new_context(accept_downloads=True)
        self.page = self.ctx.new_page()
        self.audit = audit
        self.page.on("request", lambda r: audit["requests"].append((r.method, r.url, (r.post_data_buffer or b"").decode("latin1"))))
        self.page.on("console", lambda m: audit["console"].append(m.text))
        self.page.on("pageerror", lambda e: audit["errors"].append(str(e)))
        self.backup_path = None

    def js(self, script, arg=None):
        return self.page.evaluate(script, arg)

    def open_keys(self):
        self.page.goto(self.base + "/keys")
        wait(self.page, "window.TorMail && window.TorMailCrypto")
        wait(self.page, "document.getElementById('keys-ui') && !document.getElementById('keys-ui').hidden")

    def register(self):
        self.page.goto(self.base + "/keys")
        wait(self.page, "window.TorMail")
        self.js("([u,p]) => TorMail.register(u,p)", [self.name, LOGIN_PW])
        self.open_keys()

    def login(self):
        self.page.goto(self.base + "/keys")
        wait(self.page, "window.TorMail")
        self.js("([u,p]) => TorMail.login(u,p)", [self.name, LOGIN_PW])
        self.open_keys()

    def create_key(self, tmp_path, passphrase=None):
        passphrase = passphrase or PASS[self.name]
        self.page.fill("#create-pass", passphrase)
        self.page.fill("#create-pass2", passphrase)
        self.page.check("#create-ack")
        with self.page.expect_download() as dl:
            self.page.click("#create-btn")
        path = tmp_path / f"{self.name}-{len(list(tmp_path.iterdir()))}.asc"
        dl.value.save_as(path)
        self.backup_path = path
        wait(self.page, "document.getElementById('status').textContent.startsWith('Key created')", timeout=60000)
        return path

    def unlock_ui(self, passphrase=None):
        self.page.fill("#unlock-pass", passphrase or PASS[self.name])
        self.page.click("#f-unlock button")
        wait(self.page, "document.getElementById('status').textContent === 'Unlocked.'")

    def status(self):
        return self.page.inner_text("#status")


@pytest.fixture
def audit():
    return {"requests": [], "console": [], "errors": []}


@pytest.fixture
def make(browser, server, audit):
    created = []

    def _make(name):
        s = Session(browser, server["base"], name, audit)
        created.append(s)
        return s
    yield _make
    for s in created:
        s.ctx.close()


def db_rows(server, sql, *args):
    con = sqlite3.connect(server["db"])
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def setup_user(make, tmp_path, name):
    s = make(name)
    s.register()
    s.create_key(tmp_path)
    return s


SEND = "([to, subj, body]) => TorMail.send(to, subj, body)"
OPEN_FIRST = """async () => {
  const page = await TorMail.list('inbox');
  return await TorMail.open(page.items[0], 'inbox');
}"""


def test_full_roundtrip_server_sees_only_ciphertext(make, server, audit, tmp_path):
    alice, bob = setup_user(make, tmp_path, "alice"), setup_user(make, tmp_path, "bobby")
    assert "argon2id" in alice.status(), alice.status()        # strong KDF must actually run under the CSP
    stored = alice.js("() => TorMail.localKeys('alice')[0]")
    assert alice.js("async (k) => (await openpgp.readPrivateKey({armoredKey: k})).keyPacket.s2k.type", stored) == "argon2"
    fpr = alice.page.inner_text("#fingerprint").replace(" ", "")
    assert re.fullmatch(r"[0-9A-F]{40}", fpr)

    subject, body = "Plan for Tuesday ✓ éè", "The secret launch code is PINEAPPLE-7731."
    alice.js(SEND, [["bobby"], subject, body])

    # the server's database holds ciphertext and nothing readable
    rows = db_rows(server, "select ciphertext from messages")
    assert len(rows) == 1
    blob = bytes(rows[0][0])
    assert blob.startswith(b"-----BEGIN PGP MESSAGE-----")
    for secret in (subject, body, "PINEAPPLE", "Tuesday", "launch"):
        assert secret.encode() not in blob
    everything = b"".join(bytes(c) if isinstance(c, (bytes, bytearray)) else str(c).encode()
                          for t in ("messages", "message_recipients", "user_keys", "users", "sessions")
                          for r in db_rows(server, f"select * from {t}") for c in r)
    assert b"PINEAPPLE" not in everything and b"PRIVATE KEY" not in everything

    # bob (fresh page load: key locked) unlocks through the UI and reads it
    bob.open_keys()
    assert "Locked" in bob.page.inner_text("#unlock-state")
    bob.unlock_ui()
    got = bob.js(OPEN_FIRST)
    assert got["subject"] == subject and got["body"] == body
    assert got["from"] == "alice" and got["to"] == ["bobby"]
    assert got["signature"] == "valid"
    assert got["senderKeyVerified"] is False          # nobody compared fingerprints, and the UI must not claim otherwise
    assert got["senderMismatch"] is False

    # alice reads her own sent copy
    sent = alice.js("async () => { const p = await TorMail.list('sent'); return await TorMail.open(p.items[0], 'sent'); }")
    assert sent["body"] == body and sent["signature"] == "valid"

    # privacy of the wire: no private key or passphrase ever left a browser, and nothing contacted another origin
    for method, url, post in audit["requests"]:
        assert url.startswith(server["base"]), f"external request: {url}"
        assert "PRIVATE KEY" not in post
        for p in PASS.values():
            assert p not in post
        assert LOGIN_PW not in post or url.endswith(("/register", "/login"))
    assert not [m for m in audit["console"] if "Content Security Policy" in m], audit["console"]
    assert not audit["errors"], audit["errors"]


def test_third_party_cannot_decrypt(make, server, tmp_path):
    alice, bob = setup_user(make, tmp_path, "alice"), setup_user(make, tmp_path, "bobby")
    mal = setup_user(make, tmp_path, "mallory")
    alice.js(SEND, [["bobby"], "private", "for bob only"])
    armored = bytes(db_rows(server, "select ciphertext from messages")[0][0]).decode()
    res = mal.js("""async (armored) => {
      try { await TorMailCrypto.decryptMessage({ armored, keys: TorMail.state.unlocked, senderPublic: null }); return 'decrypted'; }
      catch (e) { return e.message; } }""", armored)
    assert res.startswith("Cannot decrypt")


def test_wrong_passphrase_is_rejected(make, tmp_path):
    alice = setup_user(make, tmp_path, "alice")
    alice.open_keys()
    alice.page.fill("#unlock-pass", "definitely the wrong passphrase")
    alice.page.click("#f-unlock button")
    wait(alice.page, "document.getElementById('status').textContent === 'Wrong passphrase'")
    assert "Locked" in alice.page.inner_text("#unlock-state")


def test_weak_or_mismatched_passphrase_creates_nothing(make, server):
    alice = make("alice")
    alice.register()
    alice.page.fill("#create-pass", "short")
    alice.page.fill("#create-pass2", "short")
    alice.page.check("#create-ack")
    alice.page.evaluate("document.getElementById('f-create').noValidate = true")
    alice.page.click("#create-btn")
    wait(alice.page, "document.getElementById('status').className === 'err'")
    alice.page.fill("#create-pass", "a long enough passphrase 1")
    alice.page.fill("#create-pass2", "a different long passphrase 2")
    alice.page.click("#create-btn")
    wait(alice.page, "document.getElementById('status').textContent.includes('do not match')")
    assert db_rows(server, "select count(*) from user_keys")[0][0] == 0


def test_forged_sender_is_flagged(make, tmp_path):
    alice, bob, mal = (setup_user(make, tmp_path, n) for n in ("alice", "bobby", "mallory"))
    # mallory sends to bob but writes "from: alice" inside the signed contents
    mal.js("""async () => {
      const bobKey = (await TorMail.fetchVerifiedKey('bobby')).armored;
      const mine = await TorMail.getMyKey();
      const signer = TorMail.state.unlocked[0];
      const armored = await TorMailCrypto.encryptMessage({ signingKey: signer, senderPublic: mine.public_key,
        recipientPublics: [bobKey], from: 'alice', to: ['bobby'], subject: 'urgent', body: 'wire me money' });
      await TorMail.request('POST', '/api/messages', { recipients: ['bobby'], ciphertext: armored });
    }""")
    bob.open_keys()
    bob.unlock_ui()
    got = bob.js(OPEN_FIRST)
    assert got["from"] == "alice"                     # what the contents claim
    assert got["senderMismatch"] is True              # but the server delivered it from mallory


def test_key_change_is_detected_and_not_silent(make, tmp_path):
    alice, bob = setup_user(make, tmp_path, "alice"), setup_user(make, tmp_path, "bobby")
    alice.js(SEND, [["bobby"], "one", "first"])                       # pins bob's key
    bob.open_keys()
    bob.unlock_ui()
    bob.page.fill("#create-pass", "bobby brand new passphrase 9")
    bob.page.fill("#create-pass2", "bobby brand new passphrase 9")
    bob.page.check("#create-ack")
    with bob.page.expect_download():
        bob.page.click("#create-btn")
    wait(bob.page, "document.getElementById('status').textContent.startsWith('Key created')", timeout=60000)

    err = alice.js("""async () => { try { await TorMail.send(['bobby'], 'two', 'second'); return 'sent'; }
                       catch (e) { return e.name + ':' + e.username; } }""")
    assert err == "KeyChangedError:bobby"
    ok = alice.js("async () => { await TorMail.send(['bobby'], 'two', 'second', { acceptKeyChange: ['bobby'] }); return 'sent'; }")
    assert ok == "sent"
    # bob holds both keys locally and reads old and new mail
    bob.open_keys()
    bob.unlock_ui("bobby brand new passphrase 9")
    subjects = bob.js("""async () => { const p = await TorMail.list('inbox');
      const out = []; for (const it of p.items) { try { out.push((await TorMail.open(it, 'inbox')).subject); } catch (e) { out.push('ERR'); } }
      return out.sort(); }""")
    assert "two" in subjects          # encrypted to the new key
    # "one" was encrypted to bob's old key: opening it needs the old passphrase, which this unlock did not use
    assert subjects.count("ERR") <= 1


def test_backup_import_restores_access_on_a_new_browser(make, browser, server, tmp_path):
    alice, bob = setup_user(make, tmp_path, "alice"), setup_user(make, tmp_path, "bobby")
    bob.js(SEND, [["alice"], "hello alice", "message in a bottle"])
    backup = alice.backup_path

    fresh = make("alice")                         # empty profile: no key in localStorage
    fresh.login()
    assert "does not hold" in fresh.page.inner_text("#local-state")
    assert fresh.js("() => TorMail.localKeys('alice').length") == 0
    fresh.page.set_input_files("#import-file", str(backup))
    fresh.page.fill("#import-pass", "wrong passphrase for backup")
    fresh.page.click("#f-import button")
    wait(fresh.page, "document.getElementById('status').className === 'err'")
    fresh.page.fill("#import-pass", PASS["alice"])
    fresh.page.click("#f-import button")
    wait(fresh.page, "document.getElementById('status').textContent.startsWith('Backup imported. It matches')")
    fresh.page.wait_for_selector("#s-unlock:not([hidden])")
    fresh.unlock_ui()
    assert fresh.js(OPEN_FIRST)["body"] == "message in a bottle"


def test_importing_an_unprotected_key_is_refused(make, tmp_path):
    alice = setup_user(make, tmp_path, "alice")
    plain = alice.js("""async () => {
      const { privateKey } = await openpgp.generateKey({ type: 'curve25519', userIDs: [{ name: 'x' }], format: 'armored' });
      return privateKey; }""")
    f = tmp_path / "plain.asc"
    f.write_text(plain)
    alice.page.set_input_files("#import-file", str(f))
    alice.page.fill("#import-pass", "irrelevant")
    alice.page.click("#f-import button")
    wait(alice.page, "document.getElementById('status').textContent.includes('not passphrase-protected')")
    stored = alice.js("() => TorMail.localKeys('alice').length")
    assert stored == 1                                   # only the original key


def test_server_backup_is_opt_in_and_restorable(make, server, tmp_path):
    alice = setup_user(make, tmp_path, "alice")
    assert db_rows(server, "select count(*) from user_keys where encrypted_private_key is not null")[0][0] == 0
    alice.page.check("#sync-ack")
    alice.page.click("#f-sync-on button")
    wait(alice.page, "document.getElementById('status').textContent.startsWith('Encrypted backup stored')")
    stored = db_rows(server, "select encrypted_private_key from user_keys")[0][0]
    assert stored.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    # the stored blob is passphrase protected: it cannot be used without the passphrase
    assert alice.js("(a) => TorMailCrypto.isPassphraseProtected(a)", stored) is True
    assert alice.js("""async (a) => { try { await TorMailCrypto.unlock([a], 'not the passphrase'); return 'opened'; } catch (e) { return e.message; } }""", stored) == "Wrong passphrase"

    fresh = make("alice")
    fresh.login()
    fresh.page.click("#sync-restore")
    wait(fresh.page, "document.getElementById('status').textContent.startsWith('Backup restored')")
    fresh.page.wait_for_selector("#s-unlock:not([hidden])")
    fresh.unlock_ui()
    alice.page.click("#sync-off")
    wait(alice.page, "document.getElementById('status').textContent === 'Server backup removed.'")
    assert db_rows(server, "select count(*) from user_keys where encrypted_private_key is not null")[0][0] == 0


def test_signed_out_visitor_sees_no_key_ui(make):
    anon = make("nobody")
    anon.page.goto(anon.base + "/keys")
    wait(anon.page, "location.pathname === '/login'")       # signed-out visitors are sent to sign in
    assert not anon.page.is_visible("#keys-ui")
    assert anon.page.is_visible("#login-user")


def test_proof_of_work_solves_in_browser_in_reasonable_time(make):
    import time
    s = make("powuser")
    s.page.goto(s.base + "/keys")
    wait(s.page, "window.TorMail")
    t0 = time.time()
    s.js("([u,p]) => TorMail.register(u,p)", ["powuser", LOGIN_PW])
    assert time.time() - t0 < 20


def test_page_headers_and_published_asset_hashes(make, server):
    import hashlib
    import httpx
    r = httpx.get(server["base"] + "/keys")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    assert "<script>" not in r.text and "onclick" not in r.text          # nothing inline for the CSP to block
    manifest = httpx.get(server["base"] + "/.well-known/assets.json").json()["files"]
    for path in ("/static/vendor/openpgp.min.js", "/static/js/crypto.js", "/static/js/mail.js", "/static/js/app.js"):
        served = httpx.get(server["base"] + path).content
        assert manifest[path] == hashlib.sha256(served).hexdigest()


def test_signature_check_detects_wrong_signer(make, tmp_path):
    alice, bob, mal = (setup_user(make, tmp_path, n) for n in ("alice", "bobby", "mallory"))
    res = mal.js("""async () => {
      const bobKey = (await TorMail.fetchVerifiedKey('bobby')).armored;
      const mine = await TorMail.getMyKey();
      const armored = await TorMailCrypto.encryptMessage({ signingKey: TorMail.state.unlocked[0], senderPublic: mine.public_key,
        recipientPublics: [bobKey], from: 'mallory', to: ['bobby'], subject: 's', body: 'b' });
      return { armored, malPub: mine.public_key, alicePub: (await TorMail.fetchVerifiedKey('alice')).armored };
    }""")
    bob.open_keys()
    bob.unlock_ui()
    verdict = lambda pub: bob.js("""async ([armored, pub]) => (await TorMailCrypto.decryptMessage(
        { armored, keys: TorMail.state.unlocked, senderPublic: pub })).signature""", [res["armored"], pub])
    assert verdict(res["malPub"]) == "valid"
    assert verdict(res["alicePub"]) == "invalid"       # signed by mallory, checked against alice's key
    assert verdict(None) == "unverified"               # no sender key: the UI must not show it as verified
