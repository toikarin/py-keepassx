from pykeepassx.kdbdatabase import (
    DatabaseException,
    Header,
    HeaderException,
    RootGroup,
)
import helpers
from nose.tools import raises


def test_header():
    h = helpers.create_header()
    h2 = Header(h.to_bytearray())

    helpers.equal_headers(h, h2)


@raises(HeaderException)
def test_parse_header_len_too_small():
    h = helpers.create_header()
    Header(h.to_bytearray()[:100])


@raises(HeaderException)
def test_parse_header_invalid_signature1():
    h = helpers.create_header()
    h.signature1 = 0xDEADBEEF
    Header(h.to_bytearray())


@raises(HeaderException)
def test_parse_header_invalid_version():
    h = helpers.create_header()
    h.version = 0x00020002
    Header(h.to_bytearray())


@raises(HeaderException)
def test_parse_header_unknown_cipher():
    h = helpers.create_header()
    h.flags = 0x4
    Header(h.to_bytearray())


def test_parse_header_twofish_cipher():
    h = helpers.create_header()
    h.flags = 0x8
    h2 = Header(h.to_bytearray())
    assert h2.cipher == Header.TWOFISH_CIPHER


def test_parse_group():
    g = helpers.create_group()
    root = RootGroup().parse(g.to_bytearray(), 1, 0)

    groups = root.get_groups()
    assert len(groups) == 1
    helpers.equal_groups(g, groups[0])


def test_parse_entry():
    g = helpers.create_group()
    e = helpers.create_entry(g)
    root = RootGroup().parse(g.to_bytearray() + e.to_bytearray(), 1, 1)

    groups = root.get_groups()
    assert len(groups) == 1
    g2 = groups[0]
    helpers.equal_groups(g, g2)

    entries = g2.get_entries()
    assert len(entries) == 1
    helpers.equal_entries(e, entries[0])


def test_parse_metaentry():
    g = helpers.create_group()
    e = helpers.create_metaentry(g)
    root = RootGroup().parse(g.to_bytearray() + e.to_bytearray(), 1, 1)

    entries = root.get_groups()[0].get_meta_entries()
    assert len(entries) == 1
    helpers.equal_entries(e, entries[0])


def test_parse_with_subgroups():
    g = helpers.create_group(0)
    g2 = helpers.create_group(1)
    g3 = helpers.create_group(1)
    e = helpers.create_entry(g3)

    root = RootGroup().parse(g.to_bytearray() + g2.to_bytearray() + g3.to_bytearray() + e.to_bytearray(), 3, 1)

    groups = root.get_groups()
    assert len(groups) == 1

    rg = groups[0]
    groups = rg.get_groups()
    print len(groups)
    assert len(groups) == 2

    pg = groups[1]
    helpers.equal_groups(g3, pg)

    entries = pg.get_entries()
    assert len(entries) == 1
    helpers.equal_entries(e, entries[0])


@raises(DatabaseException)
def test_parse_group_with_no_parent():
    g = helpers.create_group(0)
    g2 = helpers.create_group(2)

    RootGroup().parse(g.to_bytearray() + g2.to_bytearray(), 2, 0)


@raises(DatabaseException)
def test_parse_entry_with_no_parent():
    g = helpers.create_group(0)
    e = helpers.create_entry(g)
    e.group_id = 1

    RootGroup().parse(g.to_bytearray() + e.to_bytearray(), 1, 1)


@raises(DatabaseException)
def test_parse_entry_less_groups_than_in_header():
    g = helpers.create_group(0)

    RootGroup().parse(g.to_bytearray(), 2, 1)
