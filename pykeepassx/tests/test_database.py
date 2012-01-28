import pytest
from pykeepassx.kdbdatabase import RootGroup
import datetime


def test_create_group():
    root = RootGroup()

    assert len(root.get_groups()) == 0

    group = root.add_group("test group")

    assert group.title == "test group"
    assert group.level == 0

    assert len(root.get_groups()) == 1
    assert group in root.get_groups()


def test_create_subgroup():
    parent_group = RootGroup().add_group("test group")
    group = parent_group.add_group("test group")

    assert len(parent_group.get_groups()) == 1
    assert group in parent_group.get_groups()
    assert group.level == 1


def test_create_group_empty_title():
    with pytest.raises(ValueError):
        RootGroup().add_group("")


def test_create_group_none_title():
    with pytest.raises(ValueError):
        RootGroup().add_group(None)


def test_remove_group():
    root = RootGroup()

    group1 = root.add_group("test group 1")
    group2 = root.add_group("test group 2")
    group3 = root.add_group("test group 3")

    assert len(root.get_groups()) == 3

    root.remove_group(group2)

    assert len(root.get_groups()) == 2
    assert group1 in root.get_groups()
    assert group2 not in root.get_groups()
    assert group3 in root.get_groups()


def test_remove_group_2():
    root = RootGroup()

    group1 = root.add_group("test group 1")
    group2 = root.add_group("test group 2")
    group3 = root.add_group("test group 3")

    assert len(root.get_groups()) == 3

    group2.remove()

    assert len(root.get_groups()) == 2
    assert group1 in root.get_groups()
    assert group2 not in root.get_groups()
    assert group3 in root.get_groups()


def test_remove_group_twice():
    root = RootGroup()

    group = root.add_group("test group 1")

    root.remove_group(group)
    with pytest.raises(ValueError):
        root.remove_group(group)


def test_remove_group_twice_2():
    root = RootGroup()

    group1 = root.add_group("test group 1")
    group2 = root.add_group("test group 2")
    group3 = root.add_group("test group 3")

    assert len(root.get_groups()) == 3

    group2.remove()
    group2.remove()

    assert len(root.get_groups()) == 2
    assert group1 in root.get_groups()
    assert group2 not in root.get_groups()
    assert group3 in root.get_groups()


def test_remove_subgroup():
    root = RootGroup()

    parent = root.add_group("parent")

    group1 = parent.add_group("test group 1")
    group2 = parent.add_group("test group 2")
    group3 = parent.add_group("test group 3")

    assert len(parent.get_groups()) == 3

    parent.remove_group(group2)

    assert len(parent.get_groups()) == 2
    assert group1 in parent.get_groups()
    assert group2 not in parent.get_groups()
    assert group3 in parent.get_groups()


def test_move_group():
    root = RootGroup()

    parent = root.add_group("parent")

    group1 = parent.add_group("test group 1")
    group2 = parent.add_group("test group 2")

    assert len(parent.get_groups()) == 2
    assert len(group1.get_groups()) == 0

    group1.move_group(group2)

    # Check group has been removed from old parent
    assert len(parent.get_groups()) == 1
    assert group2 not in parent.get_groups()

    # Check groups has been added to new parent correctly
    assert len(group1.get_groups()) == 1
    assert group2 in group1.get_groups()
    assert group2.level == group1.level + 1


def test_move_big_group():
    root = RootGroup()

    # * root        ==>  * root
    #   * group1    ==>    * group1
    #     - e1      ==>      - e1
    #     * group2  ==>    * group2
    #       - e2    ==>      - e2
    #       - e3    ==>      - e3
    #     * group3  ==>      * group4
    #       - e4    ==>       - e5
    #   * group4    ==>       - e6
    #     - e5      ==>       * group5
    #     - e6      ==>         - e7
    #     * group5  ==>         - e8
    #       - e7    ==>       * group6
    #       - e8    ==>         - e9
    #     * group6  ==>    * group3
    #       - e9    ==>      - e4

    group1 = root.add_group("group1")
    group1.add_entry("e1")
    group2 = group1.add_group("group2")
    group2.add_entry("e2")
    group2.add_entry("e3")
    group3 = group1.add_group("group3")
    group2.add_entry("e4")

    group4 = root.add_group("group4")
    group4.add_entry("e5")
    group4.add_entry("e6")
    group5 = group4.add_group("group5")
    group5.add_entry("e7")
    group5.add_entry("e8")
    group6 = group4.add_group("group6")
    group6.add_entry("e9")

    assert group1.level == 0
    assert group2.level == 1
    assert group3.level == 1
    assert group4.level == 0
    assert group5.level == 1
    assert group6.level == 1

    group2.move_group(group4)

    assert group1.level == 0
    assert group2.level == 1
    assert group3.level == 1
    assert group4.level == 2
    assert group5.level == 3
    assert group6.level == 3

    assert len(root.get_groups()) == 1
    assert group4 not in root.get_groups()
    assert group1 in root.get_groups()

    assert len(group2.get_groups()) == 1
    assert group4 in group2.get_groups()


def test_move_group_itself():
    root = RootGroup()

    parent = root.add_group("parent")
    group1 = parent.add_group("test group 1")

    with pytest.raises(ValueError):
        group1.move_group(group1)


def test_move_existing_group():
    root = RootGroup()

    parent = root.add_group("parent")
    group1 = parent.add_group("test group 1")

    with pytest.raises(ValueError):
        parent.move_group(group1)


def test_create_entry():
    group = RootGroup().add_group("test group")
    entry = group.add_entry("test entry")

    assert entry
    assert entry.title == "test entry"

    assert len(group.get_entries()) == 1
    assert entry in group.get_entries()


def test_create_entry_with_kwargs():
    group = RootGroup().add_group("test group")

    expire = tomorrow()

    entry = group.add_entry("test entry",
            url="test url",
            username="test username",
            password="test password",
            comment="test comment",
            expire=expire,
    )

    assert entry
    assert entry.title == "test entry"
    assert entry.url == "test url"
    assert entry.username == "test username"
    assert entry.comment == "test comment"
    assert entry.expire == expire


def test_create_entry_with_invalid_kwargs():
    group = RootGroup().add_group("test group")
    with pytest.raises(ValueError):
        group.add_entry("test entry", foo="bar")


def test_remove_entry():
    group = RootGroup().add_group("test group")
    entry = group.add_entry("test entry")

    assert len(group.get_entries()) == 1
    assert entry in group.get_entries()

    group.remove_entry(entry)

    assert len(group.get_entries()) == 0


def test_remove_entry_2():
    group = RootGroup().add_group("test group")
    entry = group.add_entry("test entry")

    assert len(group.get_entries()) == 1
    assert entry in group.get_entries()

    entry.remove()

    assert len(group.get_entries()) == 0


def test_move_entry():
    root = RootGroup()

    group1 = root.add_group("test group")
    group2 = root.add_group("test group 2")

    entry = group1.add_entry("test entry")

    group2.move_entry(entry)

    assert len(group1.get_entries()) == 0
    assert len(group2.get_entries()) == 1
    assert entry in group2.get_entries()


def test_move_entry_itself():
    root = RootGroup()
    group1 = root.add_group("test group")

    entry = group1.add_entry("test entry")

    with pytest.raises(ValueError):
        group1.move_entry(entry)


def tomorrow():
    return datetime.datetime.now() + datetime.timedelta(days=1)
