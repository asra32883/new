"""Chat API: membership isolation, versioned sends, groups, disappearing messages, attachments, long polling."""
import asyncio
import time
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app.models import Chat, ChatBlob, ChatMember, ChatMessage, User, utcnow
from app.services import chat as svc
from tests.conftest import csrf, new_client, register, upload_key

CT = "-----BEGIN PGP MESSAGE-----\n\n{}\n-----END PGP MESSAGE-----"
BLOB = bytes([0x85]) + b"opaque encrypted attachment bytes"


class P:
    """A registered user with a key and a client."""

    def __init__(self, app, name):
        self.c = new_client(app)
        self.h = csrf(register(self.c, name))
        upload_key(self.c, self.h, name)
        self.name = name

    def post(self, path, **kw):
        return self.c.post("/api/chats" + path, headers=self.h, **kw)

    def get(self, path=""):
        return self.c.get("/api/chats" + path)


def direct(a, b):
    r = a.post("", json={"kind": "direct", "username": b.name})
    assert r.status_code == 201, r.text
    return r.json()


def group(a, names, title="t"):
    r = a.post("", json={"kind": "group", "members": names, "meta_ciphertext": CT.format("meta-" + title)})
    assert r.status_code == 201, r.text
    return r.json()


def say(p, chat, text="hi", blobs=()):
    return p.post(f"/{chat['id']}/messages", json={"ciphertext": CT.format(text), "members_version": chat["members_version"], "blob_ids": list(blobs)})


@pytest.fixture
def trio(app):
    return P(app, "alice"), P(app, "bobby"), P(app, "carol")


def test_direct_chat_is_idempotent_and_hidden_for_peer_until_first_message(trio):
    a, b, _ = trio
    c1, c1b = direct(a, b), direct(a, b)
    assert c1["id"] == c1b["id"] and c1["kind"] == "direct"
    assert [m["username"] for m in c1["members"]] == ["alice", "bobby"]
    assert b.get("").json()["items"] == []           # nothing to see until alice writes
    assert say(a, c1).status_code == 201
    assert [i["id"] for i in b.get("").json()["items"]] == [c1["id"]]
    assert direct(b, a)["id"] == c1["id"]            # starting from the other side finds the same chat


def test_create_validation(app, trio):
    a, b, _ = trio
    assert a.post("", json={"kind": "direct", "username": "alice"}).status_code == 422          # yourself
    assert a.post("", json={"kind": "direct", "username": "ghost"}).status_code == 404
    keyless = new_client(app); register(keyless, "nokey")
    assert a.post("", json={"kind": "direct", "username": "nokey"}).status_code == 409
    assert a.post("", json={"kind": "group", "members": ["bobby"]}).status_code == 422          # meta required
    assert a.post("", json={"kind": "group", "members": [], "meta_ciphertext": CT.format("m")}).status_code == 422
    assert a.post("", json={"kind": "group", "members": ["bobby"], "meta_ciphertext": "plain title"}).status_code == 422
    assert a.post("", json={"kind": "direct", "username": "bobby", "evil": 1}).status_code == 422


def test_non_members_get_404_everywhere_and_cannot_read_or_write(trio):
    a, b, c = trio
    chat = direct(a, b)
    say(a, chat)
    cid = chat["id"]
    for call in (lambda: c.get(f"/{cid}"), lambda: c.get(f"/{cid}/messages"), lambda: say(c, chat),
                 lambda: c.post(f"/{cid}/read", json={"upto_seq": 1}), lambda: c.c.put(f"/api/chats/{cid}/ttl", headers=c.h, json={"ttl_seconds": 30}),
                 lambda: c.c.delete(f"/api/chats/{cid}/messages/1", headers=c.h), lambda: c.post(f"/{cid}/hide"),
                 lambda: c.post(f"/{cid}/blobs", content=BLOB)):
        assert call().status_code == 404
    assert c.get("").json()["items"] == []


def test_auth_and_csrf_required(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    anon = new_client(app)
    assert anon.get("/api/chats").status_code == 401
    assert anon.get(f"/api/chats/{chat['id']}/messages").status_code == 401
    r = a.c.post(f"/api/chats/{chat['id']}/messages", json={"ciphertext": CT.format("x"), "members_version": 1, "blob_ids": []})
    assert r.status_code == 403                       # session cookie but no CSRF header
    assert a.c.post("/api/chats", json={"kind": "direct", "username": "bobby"}).status_code == 403


def test_send_fetch_order_pagination_and_server_stores_only_what_it_got(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    for i in range(5):
        assert say(a if i % 2 == 0 else b, chat, f"m{i}").json()["seq"] == i + 1
    page = b.get(f"/{chat['id']}/messages?limit=3").json()
    assert [m["seq"] for m in page["items"]] == [3, 4, 5] and page["has_more"]
    older = b.get(f"/{chat['id']}/messages?before_seq=3&limit=3").json()
    assert [m["seq"] for m in older["items"]] == [1, 2] and not older["has_more"]
    newer = a.get(f"/{chat['id']}/messages?after_seq=3").json()
    assert [m["seq"] for m in newer["items"]] == [4, 5]
    assert newer["items"][0]["sender"] == "bobby"
    with app.state.session_factory() as db:
        assert db.scalar(select(ChatMessage.ciphertext).where(ChatMessage.seq == 1)) == CT.format("m0").encode()


def test_send_rejects_plaintext_oversize_and_empty_chat(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    bad = a.post(f"/{chat['id']}/messages", json={"ciphertext": "hello in the clear", "members_version": 1, "blob_ids": []})
    assert bad.status_code == 422
    huge = a.post(f"/{chat['id']}/messages", json={"ciphertext": CT.format("x" * 70_000), "members_version": 1, "blob_ids": []})
    assert huge.status_code in (413, 422)
    assert a.post(f"/{chat['id']}/messages", json={"ciphertext": CT.format("x"), "members_version": 1, "blob_ids": [], "x": 1}).status_code == 422


def test_stale_members_version_is_rejected_so_messages_are_never_encrypted_to_old_member_sets(trio):
    a, b, c = trio
    g = group(a, ["bobby"])
    assert a.post(f"/{g['id']}/members", json={"usernames": ["carol"], "members_version": g["members_version"], "meta_ciphertext": CT.format("m2")}).status_code == 204
    assert say(a, g).status_code == 409 and say(a, g).json()["detail"] == "members_changed"      # alice still has the old version
    fresh = a.get(f"/{g['id']}").json()
    assert fresh["members_version"] == g["members_version"] + 1
    assert say(a, fresh).status_code == 201
    stale_add = a.post(f"/{g['id']}/members", json={"usernames": ["carol"], "members_version": g["members_version"], "meta_ciphertext": CT.format("m3")})
    assert stale_add.status_code == 409


def test_group_roles_membership_and_history_visibility(trio):
    a, b, c = trio
    g = group(a, ["bobby"])
    assert [(m["username"], m["role"]) for m in g["members"]] == [("alice", "admin"), ("bobby", "member")]
    say(a, g, "before carol")
    # a plain member cannot add or remove
    assert b.post(f"/{g['id']}/members", json={"usernames": ["carol"], "members_version": 1, "meta_ciphertext": CT.format("x")}).status_code == 403
    assert b.c.delete(f"/api/chats/{g['id']}/members/alice?members_version=1", headers=b.h).status_code == 403
    assert a.post(f"/{g['id']}/members", json={"usernames": ["carol"], "members_version": 1, "meta_ciphertext": CT.format("m2")}).status_code == 204
    g2 = a.get(f"/{g['id']}").json()
    say(a, g2, "after carol")
    seen = c.get(f"/{g['id']}/messages").json()["items"]
    assert [m["seq"] for m in seen] == [2]                           # newcomer never receives earlier ciphertext
    assert c.get("").json()["items"][0]["meta_ciphertext"] == CT.format("m2")
    # admin removes bobby: bobby loses all access, members_version moves on
    r = a.c.delete(f"/api/chats/{g['id']}/members/bobby?members_version={g2['members_version']}", headers=a.h)
    assert r.status_code == 204
    assert b.get(f"/{g['id']}/messages").status_code == 404 and b.get("").json()["items"] == []
    assert a.get(f"/{g['id']}").json()["members_version"] == g2["members_version"] + 1


def test_leaving_promotes_an_admin_and_last_member_deletes_chat(app, trio):
    a, b, _ = trio
    g = group(a, ["bobby"])
    assert a.c.delete(f"/api/chats/{g['id']}/members/alice", headers=a.h).status_code == 204          # admin leaves
    assert [(m["username"], m["role"]) for m in b.get(f"/{g['id']}").json()["members"]] == [("bobby", "admin")]
    assert b.c.delete(f"/api/chats/{g['id']}/members/bobby", headers=b.h).status_code == 204
    with app.state.session_factory() as db:
        assert db.scalar(select(Chat).where(Chat.id == uuid.UUID(g["id"]))) is None


def test_only_the_sender_can_delete_and_it_removes_stored_ciphertext_and_attachments(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    bid = a.post(f"/{chat['id']}/blobs", content=BLOB).json()["id"]
    seq = say(a, chat, "oops", [bid]).json()["seq"]
    assert b.c.delete(f"/api/chats/{chat['id']}/messages/{seq}", headers=b.h).status_code == 404
    assert a.c.delete(f"/api/chats/{chat['id']}/messages/{seq}", headers=a.h).status_code == 204
    got = b.get(f"/{chat['id']}/messages").json()
    assert got["items"] == [] and got["deleted_seqs"] == [seq]
    with app.state.session_factory() as db:
        m = db.scalar(select(ChatMessage).where(ChatMessage.seq == seq))
        assert m.ciphertext is None and db.scalar(select(ChatBlob)) is None


def test_read_positions_and_unread_counts(trio):
    a, b, _ = trio
    chat = direct(a, b)
    for i in range(3):
        say(a, chat, f"m{i}")
    item = b.get("").json()["items"][0]
    assert item["unread"] == 3 and item["my_last_read_seq"] == 0
    assert b.post(f"/{chat['id']}/read", json={"upto_seq": 2}).status_code == 204
    assert b.get("").json()["items"][0]["unread"] == 1
    assert b.post(f"/{chat['id']}/read", json={"upto_seq": 999}).status_code == 204              # clamped to last_seq
    assert b.get("").json()["items"][0]["my_last_read_seq"] == 3
    members = {m["username"]: m["last_read_seq"] for m in a.get(f"/{chat['id']}").json()["members"]}
    assert members == {"alice": 3, "bobby": 3}
    assert b.post(f"/{chat['id']}/read", json={"upto_seq": 1}).status_code == 204                # never moves backwards
    assert b.get("").json()["items"][0]["my_last_read_seq"] == 3


def test_disappearing_messages_expire_and_are_purged(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    assert a.c.put(f"/api/chats/{chat['id']}/ttl", headers=a.h, json={"ttl_seconds": 7}).status_code == 422     # fixed choices only
    assert a.c.put(f"/api/chats/{chat['id']}/ttl", headers=a.h, json={"ttl_seconds": 30}).status_code == 204
    assert b.get(f"/{chat['id']}").json()["ttl_seconds"] == 30
    sent = say(a, chat, "temp").json()
    assert sent["expires_at"] is not None
    assert len(b.get(f"/{chat['id']}/messages").json()["items"]) == 1
    with app.state.session_factory() as db:
        db.query(ChatMessage).update({"expires_at": utcnow() - timedelta(seconds=1)})
        db.commit()
    assert b.get(f"/{chat['id']}/messages").json()["items"] == []                 # hidden immediately, even before purge
    with app.state.session_factory() as db:
        assert svc.purge(db, app.state.settings)["messages"] == 1
        assert db.scalar(select(ChatMessage)) is None
    assert a.c.put(f"/api/chats/{chat['id']}/ttl", headers=a.h, json={"ttl_seconds": None}).status_code == 204


def test_group_timer_is_admin_only(trio):
    a, b, _ = trio
    g = group(a, ["bobby"])
    assert b.c.put(f"/api/chats/{g['id']}/ttl", headers=b.h, json={"ttl_seconds": 30}).status_code == 403
    assert a.c.put(f"/api/chats/{g['id']}/ttl", headers=a.h, json={"ttl_seconds": 30}).status_code == 204


def test_hide_direct_chat_clears_my_history_only(trio):
    a, b, _ = trio
    chat = direct(a, b)
    say(a, chat, "one")
    assert b.post(f"/{chat['id']}/hide").status_code == 204
    assert b.get("").json()["items"] == []
    assert len(a.get(f"/{chat['id']}/messages").json()["items"]) == 1
    say(a, chat, "two")                                              # a new message brings it back, without old history
    item = b.get("").json()["items"][0]
    assert item["unread"] == 1
    assert [m["seq"] for m in b.get(f"/{chat['id']}/messages").json()["items"]] == [2]


def test_attachments_membership_size_and_lifecycle(app, trio):
    a, b, c = trio
    chat = direct(a, b)
    bid = a.post(f"/{chat['id']}/blobs", content=BLOB).json()["id"]
    assert b.c.get(f"/api/chats/{chat['id']}/blobs/{bid}").status_code == 404        # unattached uploads are private to the uploader
    assert a.c.get(f"/api/chats/{chat['id']}/blobs/{bid}").content == BLOB
    assert a.post(f"/{chat['id']}/blobs", content=b"").status_code == 422
    assert a.post(f"/{chat['id']}/blobs", content=b"plain text, not an OpenPGP packet").status_code == 422
    assert b.post(f"/{chat['id']}/blobs", content=BLOB).status_code == 201
    too_big = bytes([0x85]) + b"x" * (app.state.settings.chat_max_blob_bytes + 10)
    assert a.post(f"/{chat['id']}/blobs", content=too_big).status_code in (413, 422)
    # someone else's upload cannot be attached
    other = b.post(f"/{chat['id']}/blobs", content=BLOB).json()["id"]
    assert say(a, chat, "x", [other]).status_code == 422
    assert say(a, chat, "x", [str(uuid.uuid4())]).status_code == 422
    seq = say(a, chat, "with file", [bid]).json()
    assert seq["blobs"] == [bid]
    assert b.c.get(f"/api/chats/{chat['id']}/blobs/{bid}").content == BLOB
    assert c.c.get(f"/api/chats/{chat['id']}/blobs/{bid}").status_code == 404
    assert say(a, chat, "reuse", [bid]).status_code == 422                          # an upload attaches to one message only
    assert b.get(f"/{chat['id']}/messages").json()["items"][-1]["blobs"] == [bid]


def test_blob_body_limit_applies_only_to_blob_uploads(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    payload = bytes([0x85]) + b"x" * 600_000                      # above the 512 KiB default, below the blob limit
    assert a.post(f"/{chat['id']}/blobs", content=payload).status_code == 201
    big_json = a.post(f"/{chat['id']}/messages", json={"ciphertext": CT.format("x" * 600_000), "members_version": 1, "blob_ids": []})
    assert big_json.status_code == 413


def test_abandoned_uploads_are_purged_and_limited(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    for _ in range(svc.MAX_UNATTACHED_BLOBS):
        assert a.post(f"/{chat['id']}/blobs", content=BLOB).status_code == 201
    assert a.post(f"/{chat['id']}/blobs", content=BLOB).status_code == 429
    with app.state.session_factory() as db:
        db.query(ChatBlob).update({"created_at": utcnow() - timedelta(hours=2)})
        db.commit()
        assert svc.purge(db, app.state.settings)["blobs"] == svc.MAX_UNATTACHED_BLOBS


def test_chat_send_rate_limit(app, trio):
    a, b, _ = trio
    app.state.settings.chat_send_per_minute = 3
    chat = direct(a, b)
    codes = [say(a, chat, f"m{i}").status_code for i in range(5)]
    assert codes == [201, 201, 201, 429, 429]


def test_chat_creation_rate_limit_counts_probes(app, trio):
    a, _, _ = trio
    app.state.settings.chat_new_per_hour = 3
    codes = [a.post("", json={"kind": "direct", "username": f"ghost{i}"}).status_code for i in range(5)]
    assert codes == [404, 404, 404, 429, 429]


def test_account_deletion_bumps_versions_promotes_admin_and_cleans_up(app, trio):
    a, b, c = trio
    g = group(a, ["bobby", "carol"])
    d = direct(a, b)
    say(a, d, "bye")
    assert a.c.post("/api/account/delete", headers=a.h, json={"password": "correct horse 7 battery"}).status_code in (200, 204)
    after = b.get(f"/{g['id']}").json()
    assert after["members_version"] == g["members_version"] + 1
    assert sorted(m["username"] for m in after["members"]) == ["bobby", "carol"]
    assert any(m["role"] == "admin" for m in after["members"])
    items = b.get(f"/{d['id']}/messages").json()["items"]
    assert items[0]["sender"] is None                               # sender reference removed, ciphertext kept for the recipient


def test_long_poll_returns_immediately_when_changes_exist_and_times_out_empty(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    say(a, chat)
    r = b.get("")
    assert r.json()["items"] and r.json()["cursor"]
    t0 = time.time()
    quiet = b.get("?after=" + r.json()["cursor"] + "&wait=1").json()
    assert quiet["items"] == [] and 0.8 < time.time() - t0 < 4


def test_long_poll_wakes_when_a_message_arrives(app, trio):
    a, b, _ = trio
    chat = direct(a, b)
    say(a, chat, "first")
    cursor = b.get("").json()["cursor"]

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as poll, \
                httpx.AsyncClient(transport=transport, base_url="http://testserver") as send:
            for k, v in b.c.cookies.items():
                poll.cookies.set(k, v)
            for k, v in a.c.cookies.items():
                send.cookies.set(k, v)
            task = asyncio.create_task(poll.get("/api/chats", params={"after": cursor, "wait": 15}))
            await asyncio.sleep(0.5)
            t0 = time.time()
            r = await send.post(f"/api/chats/{chat['id']}/messages", headers=a.h,
                                json={"ciphertext": CT.format("second"), "members_version": chat["members_version"], "blob_ids": []})
            assert r.status_code == 201
            res = await asyncio.wait_for(task, 4)
            return res, time.time() - t0

    res, elapsed = asyncio.run(scenario())
    assert [i["id"] for i in res.json()["items"]] == [chat["id"]] and elapsed < 3


def test_long_poll_needs_auth_and_limits_waiters(app, trio):
    a, _, _ = trio
    assert new_client(app).get("/api/chats?wait=1").status_code == 401
    assert a.get("?after=not-a-date").status_code == 400
    assert a.get("?wait=999").status_code == 422
