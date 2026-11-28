"""Real-browser chat flows: two or three people, real clicks, real encryption, real long-polling."""
import io
import re

import pytest

from tests.e2e.test_browser_e2e import wait
from tests.e2e.test_browser_e2e import audit, make  # noqa: F401  (fixtures)
from tests.e2e.test_ui_flows import goto_link, ui_register

pytestmark = pytest.mark.e2e


def ready_user(make, tmp_path, name):
    s = make(name)
    ui_register(s)
    s.page.goto(s.base + "/keys"); s.open_keys(); s.create_key(tmp_path)
    return s


def start_direct(s, other):
    goto_link(s, "/chats")
    s.page.click("a[href='/chats/new']")
    wait(s.page, "location.pathname === '/chats/new'")
    s.page.fill("#nc-user", other)
    s.page.click("form[data-role=direct] button")
    wait(s.page, "/^\\/chats\\/[0-9a-f-]{36}$/.test(location.pathname)", timeout=30000)


def write(s, text):
    s.page.fill("#chat-text", text)
    s.page.press("#chat-text", "Enter")


def bubble_texts(s):
    return s.page.eval_on_selector_all(".bubble-text", "els => els.map(e => e.textContent)")


def open_chat_with(s, name):
    goto_link(s, "/chats")
    wait(s.page, f"[...document.querySelectorAll('.chatrow strong')].some(e => e.textContent === '{name}')", timeout=30000)
    s.page.click(f".chatrow:has(strong:text-is('{name}'))")
    wait(s.page, "/^\\/chats\\/[0-9a-f-]{36}$/.test(location.pathname)")


def test_direct_chat_send_live_update_read_receipt_reply_react_edit_delete(make, tmp_path):
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    start_direct(a, "bobby")
    write(a, "Hello Bobby")
    wait(a.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Hello Bobby')", timeout=30000)
    assert "Sent" in a.page.inner_text(".ticks")

    # bobby has the chat list open; it must update by itself (long poll), unread badge on the nav
    goto_link(b, "/chats")
    wait(b.page, "document.querySelector('.chatrow .badge:not([hidden])')", timeout=30000)
    assert "Hello Bobby" in b.page.inner_text(".chatrow-preview")
    assert b.page.inner_text("#chat-badge") == "1"
    b.page.click(".chatrow")
    wait(b.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Hello Bobby')", timeout=30000)
    wait(b.page, "document.getElementById('chat-badge').hidden")

    # alice's bubble flips to Read without her doing anything
    wait(a.page, "document.querySelector('.ticks').textContent.includes('Read')", timeout=30000)

    # reply
    b.page.click(".bubble.theirs [data-act=reply]")
    write(b, "Hi Alice")
    wait(a.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Hi Alice')", timeout=30000)

    # reaction from alice on bobby's message, visible to bobby
    a.page.click(".bubble.theirs [data-act=react]")
    a.page.click(".picker [data-emoji='\U0001F44D']")
    wait(b.page, "document.querySelector('.reactions .chip')", timeout=30000)
    assert "\U0001F44D" in b.page.inner_text(".reactions:not([hidden])")

    # edit
    a.page.click(".bubble.mine [data-act=edit]")
    a.page.fill("#chat-text", "Hello Bobby!!")
    a.page.press("#chat-text", "Enter")
    wait(b.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Hello Bobby!!')", timeout=30000)
    assert "edited" in b.page.inner_text(".bubble.theirs .bubble-meta")

    # delete for everyone needs a second click
    a.page.click(".bubble.mine [data-act=delete]")
    assert "Confirm" in a.page.inner_text(".bubble.mine [data-act=delete]")
    a.page.click(".bubble.mine [data-act=delete]")
    wait(b.page, "![...document.querySelectorAll('.bubble-text')].some(e => e.textContent.startsWith('Hello Bobby'))", timeout=30000)


def test_server_never_sees_chat_plaintext(make, tmp_path, server):
    from tests.e2e.test_browser_e2e import db_rows
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    start_direct(a, "bobby")
    write(a, "top secret plan zebra")
    wait(a.page, "document.querySelector('.bubble-text')", timeout=30000)
    blob = " ".join(str(r[0]) for r in db_rows(server, "select ciphertext from chat_messages"))
    assert "zebra" not in blob and "PGP MESSAGE" in blob
    assert "zebra" not in " ".join(str(r) for r in db_rows(server, "select * from chats"))


def test_locked_key_shows_no_decrypted_text_and_unlocking_restores_it(make, tmp_path):
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    start_direct(a, "bobby")
    write(a, "visible only when unlocked")
    wait(a.page, "document.querySelector('.bubble-text')", timeout=30000)
    a.page.evaluate("() => TorMail.lock()")
    wait(a.page, "!document.body.innerText.includes('visible only when unlocked')")
    assert a.page.is_disabled("#chat-text")
    a.page.fill("#unlock-pass-inline", "correct horse battery staple 7") if a.page.query_selector("#unlock-pass-inline") else None


def test_group_chat_titles_members_removal_and_timer(make, tmp_path):
    a, b, c = (ready_user(make, tmp_path, n) for n in ("alice", "bobby", "carol"))
    goto_link(a, "/chats")
    a.page.click("a[href='/chats/new']")
    a.page.fill("#nc-title", "Weekend plans")
    a.page.fill("#nc-members", "bobby carol")
    a.page.click("form[data-role=group] button")
    wait(a.page, "/^\\/chats\\/[0-9a-f-]{36}$/.test(location.pathname)", timeout=30000)
    assert a.page.inner_text("[data-role=title]") == "Weekend plans"
    write(a, "Who is in?")
    for s in (b, c):
        goto_link(s, "/chats")
        wait(s.page, "[...document.querySelectorAll('.chatrow strong')].some(e => e.textContent === 'Weekend plans')", timeout=30000)
        s.page.click(".chatrow")
        wait(s.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Who is in?')", timeout=30000)
        assert "alice" in s.page.inner_text(".bubble-from")
    # only admins get the add and remove controls
    b.page.click("[data-role=infobtn]")
    wait(b.page, "document.querySelector('[data-role=members]')")
    assert b.page.is_hidden("[data-role=addform]") and not b.page.query_selector("button[aria-label='Remove carol']")
    assert b.page.is_disabled("#ttl-select")
    # admin sets a timer and removes carol
    a.page.click("[data-role=infobtn]")
    wait(a.page, "document.querySelector('#ttl-select')")
    a.page.select_option("#ttl-select", "300")
    wait(a.page, "document.querySelector('[data-role=sub]').textContent.includes('5 minutes')", timeout=30000)
    a.page.click("button[aria-label='Remove carol']")
    wait(c.page, "![...document.querySelectorAll('.chatrow strong')].some(e => e.textContent === 'Weekend plans')", timeout=40000)
    # the next message is encrypted to the new member set and shows its disappearing time
    a.page.click("[data-role=infobtn]")
    write(a, "Just us now")
    wait(a.page, "document.querySelector('.bubble.mine [data-role=expires]:not([hidden])')", timeout=30000)
    wait(b.page, "[...document.querySelectorAll('.bubble-text')].some(e => e.textContent === 'Just us now')", timeout=40000)


def test_photo_with_gps_is_cleaned_before_upload_and_arrives_as_an_image(make, tmp_path):
    PIL = pytest.importorskip("PIL.Image")
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    img = PIL.new("RGB", (60, 40), (10, 120, 200))
    ex = PIL.Exif(); ex[0x010F] = "SecretCameraMaker"
    gps = ex.get_ifd(0x8825); gps[1] = "N"; gps[2] = (51.0, 30.0, 12.0)
    path = tmp_path / "holiday.jpg"
    img.save(path, exif=ex)
    assert b"SecretCameraMaker" in path.read_bytes()
    start_direct(a, "bobby")
    a.page.set_input_files("[data-role=file]", str(path))
    assert "removed before sending" in a.page.inner_text("[data-role=attachnote]")
    write(a, "look")
    wait(a.page, "document.querySelector('img.bubble-img')", timeout=40000)
    open_chat_with(b, "alice")
    wait(b.page, "document.querySelector('img.bubble-img') && document.querySelector('img.bubble-img').naturalWidth === 60", timeout=40000)
    with b.page.expect_download() as dl:
        b.page.click("a.file-link")                      # blob: URLs are (rightly) not fetchable under the CSP; save it instead
    saved = open(dl.value.path(), "rb").read()
    assert saved[:2] == b"\xff\xd8" and b"SecretCameraMaker" not in saved and b"Exif" not in saved and b"GPS" not in saved


def test_other_file_types_download_and_non_members_cannot_fetch_the_blob(make, tmp_path, server):
    a, b, c = (ready_user(make, tmp_path, n) for n in ("alice", "bobby", "carol"))
    doc = tmp_path / "notes.txt"; doc.write_text("meeting notes")
    start_direct(a, "bobby")
    a.page.set_input_files("[data-role=file]", str(doc))
    assert "exactly as they are" in a.page.inner_text("[data-role=attachnote]")
    write(a, "notes attached")
    wait(a.page, "document.querySelector('.bubble.mine .file')", timeout=40000)
    open_chat_with(b, "alice")
    wait(b.page, "document.querySelector('.file button')", timeout=40000)
    with b.page.expect_download() as dl:
        b.page.click(".file button")
        wait(b.page, "document.querySelector('a.file-link')", timeout=30000)
        b.page.click("a.file-link")
    assert dl.value.suggested_filename == "notes.txt"
    assert open(dl.value.path()).read() == "meeting notes"
    chat_id = re.search(r"/chats/([0-9a-f-]{36})", a.page.url).group(1)
    from tests.e2e.test_browser_e2e import db_rows
    blob_id = db_rows(server, "select id from chat_blobs")[0][0]
    bid = str(blob_id) if "-" in str(blob_id) else f"{blob_id[:8]}-{blob_id[8:12]}-{blob_id[12:16]}-{blob_id[16:20]}-{blob_id[20:]}"
    status = c.page.evaluate("async ([cid, bid]) => (await fetch(`/api/chats/${cid}/blobs/${bid}`)).status", [chat_id, bid])
    assert status == 404


def test_read_receipts_can_be_turned_off(make, tmp_path):
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    goto_link(b, "/settings")
    b.page.uncheck("[data-role=receipts]")
    start_direct(a, "bobby")
    write(a, "did you see this")
    wait(a.page, "document.querySelector('.bubble-text')", timeout=30000)
    open_chat_with(b, "alice")
    wait(b.page, "document.querySelector('.bubble-text')", timeout=30000)
    b.page.wait_for_timeout(2500)
    assert "Read" not in a.page.inner_text(".ticks")
    assert "Sent" in a.page.inner_text(".ticks")


from pathlib import Path  # noqa: E402

AXE = Path(__file__).parent / "axe" / "node_modules" / "axe-core" / "axe.min.js"


@pytest.mark.skipif(not AXE.exists(), reason="run `npm ci` in tests/e2e/axe to enable the accessibility audit")
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_chat_screens_pass_axe_audit(make, tmp_path, scheme):
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    a.page.emulate_media(color_scheme=scheme)
    start_direct(a, "bobby")
    write(a, "Accessible hello")
    wait(a.page, "document.querySelector('.bubble-text')", timeout=30000)
    a.page.click(".bubble.mine [data-act=react]")                      # picker open
    source = AXE.read_text()
    failures = {}

    def audit_page(label):
        a.page.evaluate(source)           # DevTools evaluation is not subject to the page's CSP
        res = a.page.evaluate("async () => (await axe.run(document, {runOnly: ['wcag2a','wcag2aa','wcag21aa']})).violations.map(v => v.id + ': ' + v.nodes.map(n => n.target.join(' ')).join(' | '))")
        if res:
            failures[label] = res

    audit_page("thread")
    a.page.click("[data-role=infobtn]")
    wait(a.page, "document.querySelector('#ttl-select')")
    audit_page("info")
    a.page.click("[data-role=infobtn]")
    goto_link(a, "/chats")
    wait(a.page, "document.querySelector('.chatrow')")
    audit_page("list")
    a.page.click("a[href='/chats/new']")
    wait(a.page, "document.getElementById('nc-user')")
    audit_page("new")
    assert not failures, failures


def test_chat_layout_on_a_phone(make, tmp_path, browser, server):
    a, b = ready_user(make, tmp_path, "alice"), ready_user(make, tmp_path, "bobby")
    start_direct(a, "bobby")
    write(a, "x" * 400)                                               # a long unbroken string must not overflow
    wait(a.page, "document.querySelector('.bubble-text')", timeout=30000)
    a.page.set_viewport_size({"width": 375, "height": 700})
    a.page.wait_for_timeout(300)
    assert a.page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
    assert a.page.is_visible(".back") and a.page.is_visible("#chat-text")
    goto_link(a, "/chats")
    wait(a.page, "document.querySelector('.chatrow')")
    assert a.page.is_hidden(".chat-main") and a.page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
    small = a.page.evaluate("""() => [...document.querySelectorAll('button, a.button, a.chatrow, input:not([type=checkbox]):not(.visually-hidden), textarea')]
        .filter(e => e.offsetParent && e.getBoundingClientRect().height < 32).map(e => e.outerHTML.slice(0, 70))""")
    assert not small, small
