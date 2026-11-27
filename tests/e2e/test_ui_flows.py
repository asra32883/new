"""Drives the real UI with real clicks and keystrokes (no direct TorMail calls for the flow under test)."""
import pytest

from tests.e2e.test_browser_e2e import LOGIN_PW, PASS, Session, wait, db_rows  # noqa: F401  (fixtures come via conftest)
from tests.e2e.test_browser_e2e import audit, make, setup_user  # noqa: F401

pytestmark = pytest.mark.e2e


def ui_register(s):
    p = s.page
    p.goto(s.base + "/register")
    p.fill("#reg-user", s.name); p.fill("#reg-pass", LOGIN_PW); p.fill("#reg-pass2", LOGIN_PW)
    p.click("button[data-role=submit]")
    wait(p, "location.pathname !== '/register'", timeout=60000)


def goto_link(s, href):
    s.page.click(f"nav a[href='{href}']")
    wait(s.page, f"location.pathname === '{href}'")


def compose(s, to, subject, body):
    goto_link(s, "/compose")
    s.page.fill("#compose-to", to); s.page.fill("#compose-subject", subject); s.page.fill("#compose-body", body)
    s.page.click("button[data-role=send]")
    wait(s.page, "document.getElementById('status').textContent.startsWith('Delivered to')", timeout=30000)


def test_ui_register_key_send_read_reply_delete(make, tmp_path):
    alice, bob = make("alice"), make("bobby")
    for s in (alice, bob):
        ui_register(s)
        s.page.goto(s.base + "/keys")
        s.open_keys()
        s.create_key(tmp_path)
    compose(alice, "bobby", "Hello from UI", "Body line one")
    assert "bobby" in alice.status()

    # bob: client-side navigation keeps the unlocked key
    goto_link(bob, "/inbox")
    wait(bob.page, "document.querySelector('.msglist').textContent.includes('Hello from UI')")
    bob.page.click(".msg-link")
    wait(bob.page, "document.querySelector('pre.body') && document.querySelector('pre.body').textContent.includes('Body line one')")
    trust = bob.page.inner_text("[data-role=trust]").lower()
    assert "signature" in trust

    # reply pre-fills the recipient
    bob.page.click("[data-role=reply]")
    wait(bob.page, "location.pathname === '/compose'")
    assert bob.page.input_value("#compose-to") == "alice"
    assert bob.page.input_value("#compose-subject").lower().startswith("re:")

    # search happens in the browser over decrypted text
    goto_link(bob, "/inbox")
    wait(bob.page, "document.querySelector('.msglist .msg')")
    bob.page.fill("#search", "nomatchxyz")
    wait(bob.page, "document.querySelectorAll('.msglist .msg:not([hidden])').length === 0")
    bob.page.fill("#search", "hello")
    wait(bob.page, "document.querySelectorAll('.msglist .msg:not([hidden])').length === 1")

    # delete moves it to Trash
    bob.page.click("[data-act=delete]")
    wait(bob.page, "!document.querySelector('.msglist .msg')")
    goto_link(bob, "/trash")
    wait(bob.page, "document.querySelector('.msglist .msg')")


def test_reload_requires_unlock_again_and_wrong_passphrase_is_rejected(make, tmp_path):
    s = make("alice")
    ui_register(s)
    s.page.goto(s.base + "/keys"); s.open_keys(); s.create_key(tmp_path)
    s.page.goto(s.base + "/inbox")
    wait(s.page, "document.getElementById('unlock-pass-inline')")
    s.page.fill("#unlock-pass-inline", "definitely wrong passphrase")
    s.page.click("form[data-role=unlock-form] button")
    wait(s.page, "document.getElementById('status').classList.contains('err')")
    s.page.fill("#unlock-pass-inline", PASS["alice"])
    s.page.click("form[data-role=unlock-form] button")
    wait(s.page, "!document.getElementById('unlock-pass-inline')")


def test_settings_password_change_sessions_and_delete_account(make, tmp_path, server):
    s = make("alice")
    ui_register(s)
    goto_link(s, "/settings")
    wait(s.page, "document.querySelectorAll('.sessions li').length >= 1")
    s.page.fill("#pw-current", LOGIN_PW); s.page.fill("#pw-new", "brand new password 999"); s.page.fill("#pw-new2", "brand new password 999")
    s.page.click("form[data-role=pwform] button")
    wait(s.page, "document.getElementById('status').classList.contains('ok')")
    # delete the account
    s.page.fill("#del-pass", "brand new password 999")
    s.page.check("#del-ack")
    s.page.click("form[data-role=delform] button")
    wait(s.page, "location.pathname === '/' || location.pathname === '/login'")
    assert db_rows(server, "select count(*) from users")[0][0] == 0


def test_privacy_page_is_public_and_states_limits(make):
    s = make("nobody")
    s.page.goto(s.base + "/privacy")
    wait(s.page, "document.querySelector('#view h1')")
    text = s.page.inner_text("#view").lower()
    for phrase in ("who sent messages to whom", "cannot see", "does not guarantee anonymity"):
        assert phrase in text, phrase


def test_mobile_layout_has_no_horizontal_scroll_and_large_targets(browser, server):
    ctx = browser.new_context(viewport={"width": 375, "height": 700})
    page = ctx.new_page()
    try:
        for path in ("/", "/register", "/login", "/privacy"):
            page.goto(server["base"] + path)
            wait(page, "document.querySelector('#view h1')")
            assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth"), path
            small = page.evaluate("""() => [...document.querySelectorAll('button, input:not([type=checkbox]), nav a')]
                .filter(e => e.offsetParent && e.getBoundingClientRect().height < 40).map(e => e.outerHTML.slice(0, 60))""")
            assert not small, (path, small)
    finally:
        ctx.close()


def test_keyboard_only_navigation_reaches_main_content(browser, server):
    ctx = browser.new_context()
    page = ctx.new_page()
    try:
        page.goto(server["base"] + "/login")
        wait(page, "document.getElementById('login-user')")
        page.focus("a.skip")
        assert page.evaluate("() => { const r = document.querySelector('a.skip').getBoundingClientRect(); return r.top >= 0 && r.height > 0; }")
        page.keyboard.press("Enter")
        wait(page, "document.activeElement.id === 'main'")
    finally:
        ctx.close()


AXE = __import__("pathlib").Path(__file__).parent / "axe" / "node_modules" / "axe-core" / "axe.min.js"


@pytest.mark.skipif(not AXE.exists(), reason="run `npm ci` in tests/e2e/axe to enable the accessibility audit")
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_axe_accessibility_audit(browser, server, tmp_path, scheme):
    """axe-core is injected by the test harness (bypassing CSP for this context only); it is never served by the app."""
    ctx = browser.new_context(color_scheme=scheme, bypass_csp=True)
    s = Session(browser, server["base"], "alice", {"requests": [], "console": [], "errors": []})
    s.ctx.close(); s.ctx = ctx; s.page = ctx.new_page()
    try:
        ui_register(s)
        s.page.goto(s.base + "/keys"); s.open_keys(); s.create_key(tmp_path)
        compose(s, "alice", "Note to self", "hello")
        failures = {}
        for path in ("/", "/privacy", "/inbox", "/sent", "/compose", "/settings", "/keys"):
            s.page.goto(s.base + path)
            wait(s.page, "document.querySelector('#view h1, #view h2')")
            s.page.add_script_tag(path=str(AXE))
            res = s.page.evaluate("async () => (await axe.run(document, {runOnly: ['wcag2a','wcag2aa','wcag21aa']})).violations.map(v => v.id + ': ' + v.nodes.map(n => n.target.join(' ')).join(' | '))")
            if res:
                failures[path] = res
        assert not failures, failures
    finally:
        ctx.close()


def test_show_password_toggle_reveals_and_rehides(make):
    s = make("nobody")
    s.page.goto(s.base + "/login")
    wait(s.page, "document.getElementById('login-pass')")
    assert s.page.get_attribute("#login-pass", "type") == "password"
    s.page.check("label[data-role=showpw] input")
    assert s.page.get_attribute("#login-pass", "type") == "text"
    s.page.uncheck("label[data-role=showpw] input")
    assert s.page.get_attribute("#login-pass", "type") == "password"


def test_key_auto_locks_after_idle_and_clears_decrypted_text(make, tmp_path):
    s = make("alice")
    s.page.clock.install()
    ui_register(s)
    s.page.goto(s.base + "/keys"); s.open_keys(); s.create_key(tmp_path)
    compose(s, "alice", "Secret subject", "secret body")
    goto_link(s, "/inbox")
    wait(s.page, "document.querySelector('.msglist').textContent.includes('Secret subject')")
    assert s.js("() => TorMail.state.unlocked.length") == 1
    s.page.clock.fast_forward(16 * 60 * 1000)
    wait(s.page, "TorMail.state.unlocked.length === 0")
    wait(s.page, "document.getElementById('unlock-pass-inline')")          # view rebuilt, asks for the passphrase
    assert "Secret subject" not in s.page.inner_text("#view")
    assert "locked after 15 minutes" in s.status()
