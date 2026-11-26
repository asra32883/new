import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Message, MessageRecipient, utcnow
from app.services import mailbox as svc
from tests.conftest import csrf, new_client, register


def armor(tag="x"):
    return f"-----BEGIN PGP MESSAGE-----\n\n{tag}\n-----END PGP MESSAGE-----"


@pytest.fixture
def trio(app):
    """alice, bob, mallory: three independent logged-in clients with their CSRF headers."""
    out = {}
    for name in ("alice", "bobby", "mallory"):
        c = new_client(app)
        out[name] = (c, csrf(register(c, name)))
    return out


def send(who, to, tag="x", code=201):
    c, h = who
    r = c.post("/api/messages", headers=h, json={"recipients": to if isinstance(to, list) else [to], "ciphertext": armor(tag)})
    assert r.status_code == code, r.text
    return r


def inbox(who, **params):
    return who[0].get("/api/mailbox/inbox", params=params).json()


def test_send_and_receive(trio):
    r = send(trio["alice"], "Bobby", "hello")
    assert r.json() == {"status": "delivered", "delivered_to": ["bobby"]}
    box = inbox(trio["bobby"])
    assert box["unread"] == 1 and len(box["items"]) == 1
    item = box["items"][0]
    assert item["sender"] == "alice" and item["is_read"] is False and "hello" in item["ciphertext"]
    assert inbox(trio["mallory"])["items"] == []
    sent = trio["alice"][0].get("/api/mailbox/sent").json()["items"]
    assert sent[0]["recipients"] == ["bobby"]
    assert "is_read" not in sent[0]          # no read receipts leak to the sender


def test_server_stores_only_what_it_was_given(trio, db):
    send(trio["alice"], "bobby", "opaque-blob")
    m = db.scalar(select(Message))
    assert m.ciphertext == armor("opaque-blob").encode() and m.size_bytes == len(m.ciphertext)


def test_multi_recipient_and_dedupe_and_self_send(trio):
    r = send(trio["alice"], ["bobby", "BOBBY", "mallory", "alice"])
    assert r.json()["delivered_to"] == ["bobby", "mallory", "alice"]
    assert len(inbox(trio["alice"])["items"]) == 1                      # self-send lands in own inbox
    assert len(trio["alice"][0].get("/api/mailbox/sent").json()["items"]) == 1


@pytest.mark.parametrize("payload", [
    {"recipients": ["bobby"], "ciphertext": "just plaintext"},
    {"recipients": ["bobby"], "ciphertext": "-----BEGIN PGP MESSAGE-----\nno end marker"},
    {"recipients": [], "ciphertext": "x"},
    {"recipients": ["bobby"], "ciphertext": armor("x"), "sender": "mallory"},   # unknown field
])
def test_send_validation(trio, payload):
    c, h = trio["alice"]
    assert c.post("/api/messages", headers=h, json=payload).status_code == 422
    assert inbox(trio["bobby"])["items"] == []


def test_unknown_recipient_is_all_or_nothing(trio):
    r = send(trio["alice"], ["bobby", "nosuchuser"], code=404)
    assert "nosuchuser" in r.json()["detail"]
    assert inbox(trio["bobby"])["items"] == []


def test_size_and_recipient_limits(trio, app, settings):
    app.state.settings = settings.model_copy(update={"max_message_bytes": 1024, "max_recipients": 2})
    c, h = trio["alice"]
    big = armor("a" * 2000)
    assert c.post("/api/messages", headers=h, json={"recipients": ["bobby"], "ciphertext": big}).status_code == 422
    r = c.post("/api/messages", headers=h, json={"recipients": ["bobby", "mallory", "alice"], "ciphertext": armor()})
    assert r.status_code == 422


def test_send_rate_limit_counts_probes(trio, app, settings):
    app.state.settings = settings.model_copy(update={"send_per_hour": 3})
    send(trio["alice"], "bobby")
    send(trio["alice"], "ghost1", code=404)       # failed probes consume budget
    send(trio["alice"], "ghost2", code=404)
    r = send(trio["alice"], "bobby", code=429)
    assert int(r.headers["retry-after"]) > 0
    assert len(inbox(trio["bobby"])["items"]) == 1


def test_send_requires_auth_and_csrf(trio, app):
    anon = new_client(app)
    body = {"recipients": ["bobby"], "ciphertext": armor()}
    assert anon.post("/api/messages", json=body).status_code == 401
    assert trio["alice"][0].post("/api/messages", json=body).status_code == 403
    assert trio["alice"][0].post("/api/messages", json=body, headers=trio["mallory"][1]).status_code == 403


# ---- authorization: one user cannot touch another's mailbox ----------------------------------------


def test_cross_user_access_is_denied_everywhere(trio):
    send(trio["alice"], "bobby", "secret")
    mid = inbox(trio["bobby"])["items"][0]["id"]
    mal, mh = trio["mallory"]
    for folder in ("inbox", "trash", "sent"):
        assert mal.get(f"/api/mailbox/{folder}/{mid}").status_code == 404
        assert mal.delete(f"/api/mailbox/{folder}/{mid}", headers=mh).status_code == 404
    assert mal.post(f"/api/mailbox/inbox/{mid}/read", headers=mh, json={"is_read": True}).status_code == 404
    assert mal.post(f"/api/mailbox/trash/{mid}/restore", headers=mh).status_code == 404
    # indistinguishable from a message that never existed
    assert mal.get(f"/api/mailbox/inbox/{uuid.uuid4()}").status_code == 404
    # victim state untouched
    assert inbox(trio["bobby"])["items"][0]["is_read"] is False and len(inbox(trio["bobby"])["items"]) == 1


def test_sender_cannot_read_via_recipient_folders_and_vice_versa(trio):
    send(trio["alice"], "bobby")
    mid = inbox(trio["bobby"])["items"][0]["id"]
    a, ah = trio["alice"]
    b, bh = trio["bobby"]
    assert a.get(f"/api/mailbox/inbox/{mid}").status_code == 404      # sender is not a recipient
    assert b.get(f"/api/mailbox/sent/{mid}").status_code == 404       # recipient is not the sender
    assert a.get(f"/api/mailbox/sent/{mid}").status_code == 200
    assert b.get(f"/api/mailbox/inbox/{mid}").status_code == 200
    assert a.post(f"/api/mailbox/inbox/{mid}/read", headers=ah, json={"is_read": True}).status_code == 404


def test_unauthenticated_mailbox_access(app, trio):
    send(trio["alice"], "bobby")
    mid = inbox(trio["bobby"])["items"][0]["id"]
    anon = new_client(app)
    for path in ("/api/mailbox/inbox", "/api/mailbox/sent", f"/api/mailbox/inbox/{mid}"):
        assert anon.get(path).status_code == 401


def test_bad_folder_and_ids(trio):
    c, h = trio["alice"]
    assert c.get("/api/mailbox/drafts").status_code == 422
    assert c.get("/api/mailbox/inbox/not-a-uuid").status_code == 422
    assert c.get("/api/mailbox/inbox", params={"cursor": "!!!"}).status_code == 400


# ---- read state, delete, restore, purge --------------------------------------------------------------


def test_read_unread_toggle(trio):
    send(trio["alice"], "bobby")
    b, bh = trio["bobby"]
    mid = inbox(trio["bobby"])["items"][0]["id"]
    assert b.post(f"/api/mailbox/inbox/{mid}/read", headers=bh, json={"is_read": True}).status_code == 204
    box = inbox(trio["bobby"])
    assert box["unread"] == 0 and box["items"][0]["is_read"] is True
    assert b.post(f"/api/mailbox/inbox/{mid}/read", headers=bh, json={"is_read": False}).status_code == 204
    assert inbox(trio["bobby"])["unread"] == 1


def test_delete_flow_inbox_trash_restore_permanent(trio, db):
    send(trio["alice"], "bobby")
    b, bh = trio["bobby"]
    mid = inbox(trio["bobby"])["items"][0]["id"]
    assert b.delete(f"/api/mailbox/inbox/{mid}", headers=bh).json() == {"result": "trashed"}
    assert inbox(trio["bobby"])["items"] == []
    assert b.get("/api/mailbox/trash").json()["items"][0]["id"] == mid
    assert b.get(f"/api/mailbox/inbox/{mid}").status_code == 404
    assert b.post(f"/api/mailbox/trash/{mid}/restore", headers=bh).status_code == 204
    assert inbox(trio["bobby"])["items"][0]["id"] == mid
    b.delete(f"/api/mailbox/inbox/{mid}", headers=bh)
    assert b.delete(f"/api/mailbox/trash/{mid}", headers=bh).json() == {"result": "deleted"}
    assert b.get("/api/mailbox/trash").json()["items"] == []
    # sender still holds it, so the ciphertext row survives
    assert db.scalar(select(Message)) is not None


def test_message_removed_when_last_holder_deletes(trio, db):
    send(trio["alice"], "bobby")
    a, ah = trio["alice"]
    b, bh = trio["bobby"]
    mid = inbox(trio["bobby"])["items"][0]["id"]
    assert a.delete(f"/api/mailbox/sent/{mid}", headers=ah).json() == {"result": "deleted"}
    assert a.get("/api/mailbox/sent").json()["items"] == []
    assert b.get(f"/api/mailbox/inbox/{mid}").status_code == 200       # recipient unaffected
    db.expire_all()
    assert db.scalar(select(Message)) is not None
    b.delete(f"/api/mailbox/inbox/{mid}", headers=bh)
    b.delete(f"/api/mailbox/trash/{mid}", headers=bh)
    db.expire_all()
    assert db.scalar(select(Message)) is None and db.scalar(select(MessageRecipient)) is None


def test_trash_purge_after_retention(trio, db, settings):
    send(trio["alice"], "bobby", "old")
    send(trio["alice"], "bobby", "recent")
    b, bh = trio["bobby"]
    ids = [i["id"] for i in inbox(trio["bobby"])["items"]]
    for mid in ids:
        b.delete(f"/api/mailbox/inbox/{mid}", headers=bh)
    old = db.scalar(select(MessageRecipient).where(MessageRecipient.message_id == uuid.UUID(ids[1])))
    old.deleted_at = utcnow() - timedelta(days=31)
    db.commit()
    assert svc.purge_trash(db, settings) == 1
    assert [i["id"] for i in b.get("/api/mailbox/trash").json()["items"]] == [ids[0]]


def test_account_deletion_keeps_recipients_copy_without_sender(trio, db):
    send(trio["alice"], "bobby")
    a, ah = trio["alice"]
    assert a.post("/api/account/delete", headers=ah, json={"password": "correct horse 7 battery"}).status_code == 204
    item = inbox(trio["bobby"])["items"][0]
    assert item["sender"] is None
    b, bh = trio["bobby"]
    b.delete(f"/api/mailbox/inbox/{item['id']}", headers=bh)
    b.delete(f"/api/mailbox/trash/{item['id']}", headers=bh)
    db.expire_all()
    assert db.scalar(select(Message)) is None          # no sender, no recipients: gone


# ---- pagination -------------------------------------------------------------------------------------


def test_keyset_pagination_is_complete_ordered_and_stable(trio):
    for n in range(7):
        send(trio["alice"], "bobby", f"m{n}")
    seen, cursor, pages = [], None, 0
    while True:
        page = inbox(trio["bobby"], limit=3, **({"cursor": cursor} if cursor else {}))
        seen += [i["ciphertext"] for i in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and len(seen) == 7 and len(set(seen)) == 7
    assert [s.split("\n")[2] for s in seen] == [f"m{n}" for n in range(6, -1, -1)]   # newest first


def test_new_mail_during_pagination_does_not_duplicate(trio):
    for n in range(4):
        send(trio["alice"], "bobby", f"m{n}")
    first = inbox(trio["bobby"], limit=2)
    send(trio["alice"], "bobby", "late")
    second = inbox(trio["bobby"], limit=2, cursor=first["next_cursor"])
    ids = [i["id"] for i in first["items"] + second["items"]]
    assert len(ids) == len(set(ids)) == 4


def test_limit_is_capped(trio, app, settings):
    app.state.settings = settings.model_copy(update={"page_size_max": 2})
    for n in range(4):
        send(trio["alice"], "bobby", f"m{n}")
    assert len(inbox(trio["bobby"], limit=50)["items"]) == 2
    assert trio["bobby"][0].get("/api/mailbox/inbox", params={"limit": 0}).status_code == 422
