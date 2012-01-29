from pykeepassx.kdbdatabase import Group, Entry, Header
from pykeepassx import crypto
from pykeepassx import utils

import datetime


def equal_headers(h, h2):
    assert h2.signature1 == h.signature1
    assert h2.signature2 == h.signature2
    assert h2.flags == h.flags
    assert h2.version == h.version
    assert h2.final_random_seed == h.final_random_seed
    assert h2.encryption_iv == h.encryption_iv
    assert h2.transf_random_seed == h.transf_random_seed
    assert h2.contents_hash == h.contents_hash
    assert h2.num_groups == h.num_groups
    assert h2.num_entries == h.num_entries
    assert h2.key_transf_rounds == h.key_transf_rounds

    assert h2.to_bytearray() == h.to_bytearray()


def equal_groups(g, g2):
    assert g2.group_id == g.group_id
    assert g2.title == g.title
    assert g2.image == g.image
    assert g2.level == g.level


def equal_entries(e, e2):
    assert e2.uuid == e.uuid
    assert e2.group_id == e.group_id
    assert e2.image == e.image
    assert e2.title == e.title
    assert e2.url == e.url
    assert e2.username == e.username
    assert e2.password == e.password
    assert e2.comment == e.comment
    assert e2.creation == e.creation
    assert e2.last_mod == e.last_mod
    assert e2.last_access == e.last_access
    assert e2.expire == e.expire
    assert e2.binary_desc == e.binary_desc
    assert e2.binary == e.binary


def create_header():
    h = Header()

    h.num_groups = 2
    h.num_entries = 3

    h.final_random_seed = crypto.randomize(16)
    h.encryption_iv = crypto.randomize(16)
    h.transf_random_seed = crypto.randomize(32)
    h.contents_hash = crypto.sha256("foo")

    return h


def create_group(level=0):
    g = Group()
    g.group_id = crypto.randomize_int(4)
    g.title = "test"
    g.creation = utils.now()
    g.last_mod = utils.now()
    g.last_access = utils.now()
    g.image = 1
    g.level = level

    return g


def create_entry(group):
    now = utils.now()

    e = Entry()
    e.uuid = utils.generate_uuid()
    e.group_id = group.group_id
    e.image = 1
    e.title = "test title"
    e.url = "http://www.example.com"
    e.username = "test username"
    e.password = "test password"
    e.comment = "test comment"
    e.creation = now + datetime.timedelta(minutes=10)
    e.last_mod = now + datetime.timedelta(minutes=20)
    e.last_access = now + datetime.timedelta(minutes=30)
    e.expire = now + datetime.timedelta(minutes=40)
    e.binary_desc = "test binary desc"
    e.binary = bytearray('test binary\x00')

    return e


def create_metaentry(group):
    now = utils.now()

    e = Entry()
    e.uuid = utils.generate_uuid()
    e.group_id = group.group_id
    e.image = 0
    e.title = "Meta-Info"
    e.url = "$"
    e.username = "SYSTEM"
    e.password = ""
    e.comment = "KPX_CUSTOM_ICONS_4"
    e.creation = now + datetime.timedelta(minutes=10)
    e.last_mod = now + datetime.timedelta(minutes=20)
    e.last_access = now + datetime.timedelta(minutes=30)
    e.expire = now + datetime.timedelta(minutes=40)
    e.binary_desc = "bin-stream"
    e.binary = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    return e


def dump(db):
    for rg in db.root().get_groups():
        _dump_group(rg, 1)


def _dump_group(g, level):
    print "{indent} * {title}".format(indent=level * " ", title=g.title)

    for e in g.get_entries():
        print "{indent} - {title}".format(indent=level * " ", title=e.title)
    for g in g.get_groups():
        _dump_group(g, level + 1)
