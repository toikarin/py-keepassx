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

    def to_bytearray(self):
        args = [self.signature1, self.signature2, self.flags, self.version]
        args.extend(bytearray(self.final_random_seed))
        args.extend(bytearray(self.encryption_iv))
        args.append(self.num_groups)
        args.append(self.num_entries)
        args.extend(bytearray(self.contents_hash))
        args.extend(bytearray(self.transf_random_seed))
        args.append(self.key_transf_rounds)

        return struct.pack(Header.PACK_STR, *args)

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
        self.creation = None
        self.last_mod = None
        self.last_access = None
        self.expire = None
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

    def to_bytearray(self):
        data = (
            Entry.FIELD_TYPE_UUID, 16, self.uuid.bytes,
            Entry.FIELD_TYPE_GROUP_ID, 4, self.group_id,
            Entry.FIELD_TYPE_IMAGE, 4, self.image,
            Entry.FIELD_TYPE_TITLE, xstr(self.title),
            Entry.FIELD_TYPE_URL, xstr(self.url),
            Entry.FIELD_TYPE_USERNAME, xstr(self.username),
            Entry.FIELD_TYPE_PASSWORD, xstr(self.password),
            Entry.FIELD_TYPE_COMMENT, xstr(self.comment),
            Entry.FIELD_TYPE_CREATION, 5, from_datetime(self.creation),
            Entry.FIELD_TYPE_LAST_MOD, 5, from_datetime(self.last_mod),
            Entry.FIELD_TYPE_LAST_ACCESS, 5, from_datetime(self.last_access),
            Entry.FIELD_TYPE_EXPIRE, 5, from_datetime(self.expire),
            Entry.FIELD_TYPE_BINARY_DESC, xstr(self.binary_desc),
            Entry.FIELD_TYPE_BINARY, xstr(self.binary, True),
            Entry.FIELD_TYPE_END, 0
        )

        pack_fmt = '<HI16c HII HII HI{title_len}B HI{url_len}B HI{username_len}B HI{password_len}B'
        pack_fmt += ' HI{comment_len}B HI5B HI5B HI5B HI5B HI{binary_desc_len}B HI{binary_len}B HI'

        pack_fmt = pack_fmt.format(
            title_len=xlen(self.title),
            url_len=xlen(self.url),
            username_len=xlen(self.username),
            password_len=xlen(self.password),
            comment_len=xlen(self.comment),
            binary_desc_len=xlen(self.binary_desc),
            binary_len=xlen(self.binary, True),
        )

        return struct.pack(pack_fmt, *utils.flatten(data))


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
        self.creation = None
        self.last_mod = None
        self.last_access = None
        self.expire = None
        self.image = None
        self.level = None
        self.children = list()
        self.entries = list()
        self.flags = 0  # unused

    def to_bytearray(self):
        data = (
            Group.FIELD_TYPE_ID, 4, self.id,
            Group.FIELD_TYPE_TITLE, xstr(self.title),
            Group.FIELD_TYPE_CREATION, 5, from_datetime(self.creation),
            Group.FIELD_TYPE_LAST_MOD, 5, from_datetime(self.last_mod),
            Group.FIELD_TYPE_LAST_ACCESS, 5, from_datetime(self.last_access),
            Group.FIELD_TYPE_EXPIRE, 5, from_datetime(self.expire),
            Group.FIELD_TYPE_IMAGE, 4, self.image,
            Group.FIELD_TYPE_LEVEL, 2, self.level,
            Group.FIELD_TYPE_FLAGS, 4, self.flags,
            Group.FIELD_TYPE_END, 0
        )

        pack_fmt = '<HII HI{title_len}B HI5B HI5B HI5B HI5B HII HIH HII HI'.format(
            title_len=xlen(self.title),
        )

        return struct.pack(pack_fmt, *utils.flatten(data))


class Body(object):
    def __init__(self, unencrypted_data, num_groups, num_entries):
        self._data = unencrypted_data
        self._num_groups = num_groups
        self._num_entries = num_entries

        self._groups = list()
        self._entries = list()

        self.root = Group()
        self.meta_entries = list()

    def parse(self):
        self._groups, pos = self._generic_parse(Group, self._num_groups, 0, self._read_group_field)
        self._entries, pos = self._generic_parse(Entry, self._num_entries, pos, self._read_entry_field)

        # Separate entries and meta entries
        entries, self.meta_entries = utils.partition(lambda x: not x.is_meta_stream(), self._entries)

        self._create_group_tree(self._groups)
        self._map_entries_to_groups(self._groups, entries)

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
        self._body = Body(self._unencrypted_data, self._header.num_groups, self._header.num_entries)
        self._body.parse()

    def get_root_group(self):
        return self._body.root

    def _generate_key(self, password):
        raw_master_key = self._get_master_key(password)
        master_key = crypto.transform(raw_master_key, self._header.transf_random_seed, self._header.key_transf_rounds)
        return crypto.sha256([self._header.final_random_seed, master_key])

    def _get_master_key(self, pw):
        pw_cp1252 = pw.decode("cp1252")
        return crypto.sha256(pw_cp1252)

    def _get_lockfile(self):
        return "{0}.lock".format(self._filename)


def xstr(s, is_binary=False):
    if s:
        if not is_binary:
            ba = bytearray(s)
            ba.append(0)
        else:
            ba = s

        return (len(ba), ba)
    else:
        return (1, 0)


def xlen(x, is_binary=False):
    if not is_binary:
        return len(x) + 1 if x else 1
    else:
        return len(x) if x else 1


def from_datetime(d):
    if not d:
        return _from_datetime(0, 0, 0, 0, 0, 0)
    else:
        return _from_datetime(d.year, d.month, d.day, d.hour, d.minute, d.second)


def _from_datetime(year, month, day, hour, minute, second):
    s = [0, 0, 0, 0, 0]

    s[0] = year >> 6 & 0x0000003F
    s[1] = ((year & 0x0000003F) << 2) | (month >> 2 & 0x00000003)
    s[2] = ((month & 0x00000003) << 6) | ((day & 0x0000001F) << 1) | ((hour >> 4) & 0x00000001)
    s[3] = ((hour & 0x0000000F) << 4) | ((minute >> 2) & 0x0000000F)
    s[4] = ((minute & 0x00000003) << 6) | (second & 0x0000003F)

    return s


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
