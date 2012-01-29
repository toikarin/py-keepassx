from pykeepassx import FileDatabase

import os
import tempfile


def test_create_file():
    (_, filename) = tempfile.mkstemp(text=True)

    try:
        # Create file
        db = FileDatabase(filename)
        root = db.get_root_group()

        group = root.add_group("test group")
        group.add_entry("test entry")

        db.save("test password")

        # Read file
        db2 = FileDatabase(filename)
        root2 = db2.open("test password")

        assert len(root2.get_groups()) == 1
        group2 = root2.get_groups()[0]

        assert group2.title == "test group"
        assert len(group2.get_entries()) == 1

        assert group2.get_entries()[0].title == "test entry"
    finally:
        if os.path.exists(filename):
            os.unlink(filename)
