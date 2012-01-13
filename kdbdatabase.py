import uuid
import struct
import getpass
import datetime
import os

import utils
import crypto


class DatabaseException(Exception):
    pass


class HeaderException(DatabaseException):
    pass


class Header(object):
    DB_HEADER_SIZE = 124
    PWM_DBSIG_1 = 0x9AA2D903
    PWM_DBSIG_2 = 0xB54BFB65
    PWM_DBVER_DW = 0x00030002
    PWM_FLAG_RIJNDAEL = 2
    PWM_FLAG_TWOFISH = 8
    RIJNDAEL_CIPHER = 0
    TWOFISH_CIPHER = 1

    PACK_STR = '<4I 16B 16B II 32B 32B I'

    def __init__(self, data=None):
        if not data:
            self.signature1 = Header.PWM_DBSIG_1
            self.signature2 = Header.PWM_DBSIG_2
            self.flags = Header.PWM_FLAG_RIJNDAEL
            self.version = Header.PWM_DBVER_DW
            self.final_random_seed = None
            self.encryption_iv = None
            self.num_groups = 0
            self.num_entries = 0
            self.contents_hash = None
            self.transf_random_seed = None
            self.key_transf_rounds = 0
        else:
            self._parse_header(data)

    def _parse_header(self, data):
        if len(data) < Header.DB_HEADER_SIZE:
            raise HeaderException("Unexpected file size (DB_TOTAL_SIZE < DB_HEADER_SIZE)")

        unpacked = struct.unpack_from(Header.PACK_STR, data)

        self.signature1, self.signature2, self.flags, self.version = unpacked[:4]
        self.final_random_seed = str(bytearray(unpacked[4:20]))
        self.encryption_iv = str(bytearray(unpacked[20:36]))
        self.num_groups, self.num_entries = unpacked[36:38]
        self.contents_hash = str(bytearray(unpacked[38:70]))
        self.transf_random_seed = str(bytearray(unpacked[70:102]))
        self.key_transf_rounds = unpacked[102]

        if self.signature1 != Header.PWM_DBSIG_1 or self.signature2 != Header.PWM_DBSIG_2:
            raise HeaderException("Wrong signature")

        if (self.version & 0xFFFFFF00) != (Header.PWM_DBVER_DW & 0xFFFFFF00):
            raise HeaderException("Unsupported file version")

        if (self.flags & Header.PWM_FLAG_RIJNDAEL):
            self.cipher = Header.RIJNDAEL_CIPHER
        elif (self.flags & Header.PWM_FLAG_TWOFISH):
            self.cipher = Header.TWOFISH_CIPHER
        else:
            raise HeaderException("Unknown Encryption Algorithm.")


class Entry(object):
    FIELD_TYPE_UUID = 0x0001
    FIELD_TYPE_GROUP_ID = 0x0002
    FIELD_TYPE_IMAGE = 0x0003
    FIELD_TYPE_TITLE = 0x0004
    FIELD_TYPE_URL = 0x0005
    FIELD_TYPE_USERNAME = 0x0006
    FIELD_TYPE_PASSWORD = 0x0007
    FIELD_TYPE_COMMENT = 0x0008
    FIELD_TYPE_CREATION = 0x0009
    FIELD_TYPE_LAST_MOD = 0x000A
    FIELD_TYPE_LAST_ACCESS = 0x000B
    FIELD_TYPE_EXPIRE = 0x000C
    FIELD_TYPE_BINARY_DESC = 0x000D
    FIELD_TYPE_BINARY = 0x000E
    FIELD_TYPE_END = 0xFFFF

    def __init__(self):
        self.uuid = None
        self.group_id = None
        self.image = None
        self.title = None
        self.url = None
        self.username = None
        self.password = None
        self.comment = None
        self.binary_desc = None
        self.binary = None

    def is_meta_stream(self):
        if not self.binary:
            return False
        if not self.comment:
            return False
        if self.binary_desc != "bin-stream":
            return False
        if self.title != "Meta-Info":
            return False
        if self.username != "SYSTEM":
            return False
        if self.url != "$":
            return False
        if self.image:
            return False
        return True


class Group(object):
    FIELD_TYPE_ID = 0x0001
    FIELD_TYPE_TITLE = 0x0002
    FIELD_TYPE_CREATION = 0x0003
    FIELD_TYPE_LAST_MOD = 0x0004
    FIELD_TYPE_LAST_ACCESS = 0x0005
    FIELD_TYPE_EXPIRE = 0x0006
    FIELD_TYPE_IMAGE = 0x0007
    FIELD_TYPE_LEVEL = 0x0008
    FIELD_TYPE_FLAGS = 0x0009
    FIELD_TYPE_END = 0xFFFF

    def __init__(self):
        self.id = None
        self.title = None
        self.image = None
        self.level = None
        self.children = list()
        self.entries = list()


class Body(object):
    def __init__(self, unencrypted_data, num_groups, num_entries):
        self._data = unencrypted_data
        self._num_groups = num_groups
        self._num_entries = num_entries

        self.root = Group()
        self.meta_entries = list()

    def parse(self):
        groups, pos = self._generic_parse(Group, self._num_groups, 0, self._read_group_field)
        entries, pos = self._generic_parse(Entry, self._num_entries, pos, self._read_entry_field)

        # Separate entries and meta entries
        entries, self.meta_entries = utils.partition(lambda x: not x.is_meta_stream(), entries)

        self._create_group_tree(groups)
        self._map_entries_to_groups(groups, entries)

    def _map_entries_to_groups(self, groups, entries):
        gdict = dict()
        for g in groups:
            gdict[g.id] = g

        for e in entries:
            gdict[e.group_id].entries.append(e)

    def _create_group_tree(self, groups):
        num_groups = len(groups)

        for i in range(num_groups):
            if groups[i].level == 0:
                self.root.children.append(groups[i])
            else:
                parent = None
                for j in reversed(range(i)):
                    if groups[j].level == groups[i].level - 1:
                        parent = groups[j]
                        break

                if not parent:
                    raise "!"

                parent.children.append(groups[i])

    def _generic_parse(self, cls, num_entries, pos, func):
        cur_entry = 0
        cur_obj = cls()
        entries = list()

        while cur_entry < num_entries:
            field_type, field_size = struct.unpack_from("<HI", self._data[pos:])
            pos += 6

            retval = func(cur_obj, field_type, self._data[pos:pos + field_size])

            if field_type == 0xFFFF and retval:
                entries.append(cur_obj)
                cur_obj = cls()
                cur_entry += 1

            pos += field_size

        return entries, pos

    def _read_entry_field(self, obj, field_type, field_data):
        if field_type == 0x0000:
            # ignore field
            pass
        elif field_type == Entry.FIELD_TYPE_UUID:
            obj.uuid = uuid.UUID(bytes=field_data)
        elif field_type == Entry.FIELD_TYPE_GROUP_ID:
            obj.group_id = struct.unpack_from('<I', field_data)[0]
        elif field_type == Entry.FIELD_TYPE_IMAGE:
            obj.image = struct.unpack_from('<I', field_data)[0]
        elif field_type == Entry.FIELD_TYPE_TITLE:
            obj.title = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_URL:
            obj.url = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_USERNAME:
            obj.username = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_PASSWORD:
            obj.password = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_COMMENT:
            obj.comment = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_CREATION:
            obj.creation = to_datetime(field_data)
        elif field_type == Entry.FIELD_TYPE_LAST_MOD:
            obj.last_mod = to_datetime(field_data)
        elif field_type == Entry.FIELD_TYPE_LAST_ACCESS:
            obj.last_access = to_datetime(field_data)
        elif field_type == Entry.FIELD_TYPE_EXPIRE:
            obj.expire = to_datetime(field_data)
        elif field_type == Entry.FIELD_TYPE_BINARY_DESC:
            obj.binary_desc = str(field_data)[:-1]
        elif field_type == Entry.FIELD_TYPE_BINARY:
            obj.binary = bytearray(field_data)
        elif field_type == Entry.FIELD_TYPE_END:
            pass
        else:
            return False  # field unsupported

        return True  # field supported

    def _read_group_field(self, obj, field_type, field_data):
        if field_type == 0x0000:
            # ignore field
            pass
        elif field_type == Group.FIELD_TYPE_ID:
            obj.id = struct.unpack_from('<I', field_data)[0]
        elif field_type == Group.FIELD_TYPE_TITLE:
            obj.title = str(field_data)[:-1]
        elif Group.FIELD_TYPE_CREATION >= field_type <= Group.FIELD_TYPE_EXPIRE:
            # not longer used by KeePassX but part of the KDB format
            pass
        elif field_type == Group.FIELD_TYPE_IMAGE:
            obj.image = struct.unpack_from('<I', field_data)[0]
        elif field_type == Group.FIELD_TYPE_LEVEL:
            obj.level = struct.unpack_from('<H', field_data)[0]
        elif field_type == Group.FIELD_TYPE_FLAGS:
            # not longer used by KeePassX but part of the KDB format
            pass
        elif field_type == Group.FIELD_TYPE_END:
            pass
        else:
            return False  # field unsupported

        return True  # field supported


class Database(object):
    def __init__(self, filename):
        self._data = None
        self._header = None
        self._unencrypted_data = None
        self._filename = filename

    def is_locked(self):
        return os.path.exists(self._get_lockfile())

    def lock(self):
        if self.is_locked():
            return

        with open(self._get_lockfile(), 'a'):
            pass

    def unlock(self):
        try:
            os.unlink(self._get_lockfile())
        except OSError:
            pass

    def open(self, password):
        self.read_file()
        self.parse_header()
        self.decrypt(password)
        self.parse_body()
        return self.get_root_group()

    def read_file(self):
        try:
            with open(self._filename, "rb") as f:
                self._data = f.read()
        except IOError as e:
            raise DatabaseException(e)

        if len(self._data) < Header.DB_HEADER_SIZE:
            raise DatabaseException("Unexpected file size (DB_TOTAL_SIZE < DB_HEADER_SIZE)")

        self.lock()

    def parse_header(self):
        self._header = Header(self._data[:Header.DB_HEADER_SIZE])

    def decrypt(self, password):
        final_key = self._generate_key(password)

        if (self._header.cipher == Header.RIJNDAEL_CIPHER):
            self._unencrypted_data = crypto.decrypt_aes(final_key, self._header.encryption_iv, self._data[Header.DB_HEADER_SIZE:])

            crypto_size = len(self._unencrypted_data)
        else:
            raise DatabaseException("Unknown encryption algorithm.")

        if crypto_size > 214783446 or (not crypto_size and self.num_groups):
            raise DatabaseException("Decryption failed. The key is wrong or the file is damaged.")

        contents_hash = crypto.sha256(self._unencrypted_data[:crypto_size])

        if self._header.contents_hash != contents_hash:
            raise DatabaseException("Hash test failed. The key is wrong or the file is damaged.")

    def parse_body(self):
        self.bp = Body(self._unencrypted_data, self._header.num_groups, self._header.num_entries)
        self.bp.parse()

    def get_root_group(self):
        return self.bp.root

    def _generate_key(self, password):
        raw_master_key = self._get_master_key(password)
        master_key = crypto.transform(raw_master_key, self._header.transf_random_seed, self._header.key_transf_rounds)
        return crypto.sha256([self._header.final_random_seed, master_key])

    def _get_master_key(self, pw):
        pw_cp1252 = pw.decode("cp1252")
        return crypto.sha256(pw_cp1252)

    def _get_lockfile(self):
        return "{0}.lock".format(self._filename)


def to_datetime(data):
    dw1, dw2, dw3, dw4, dw5 = struct.unpack_from('<BBBBB', data)

    y = (dw1 << 6) | (dw2 >> 2)
    mon = ((dw2 & 0x00000003) << 2) | (dw3 >> 6)
    d = (dw3 >> 1) & 0x0000001F
    h = ((dw3 & 0x00000001) << 4) | (dw4 >> 4)
    m = ((dw4 & 0x0000000F) << 2) | (dw5 >> 6)
    s = dw5 & 0x0000003F

    return datetime.datetime(year=y, month=mon, day=d, hour=h, minute=m, second=s)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = raw_input("Filename: ")

    db = Database(filename)
    pw = getpass.getpass("Password: ")
    db.open(pw)

    for rg in db.get_root_group().children:
        utils.print_group_tree(rg)
