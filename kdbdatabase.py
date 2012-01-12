from Crypto.Cipher import AES
import uuid
import struct
import getpass
import datetime
import utils
import os


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

    def parse_header(self, data):
        if len(data) < Header.DB_HEADER_SIZE:
            raise HeaderException("Unexpected file size (DB_TOTAL_SIZE < DB_HEADER_SIZE)")

        self.signature1, self.signature2, self.flags, self.version = struct.unpack_from('<IIII', data)
        self.final_random_seed = str(bytearray(struct.unpack_from("16B", data, 16)))
        self.encryption_iv = str(bytearray(struct.unpack_from("16B", data, 32)))
        self.num_groups, self.num_entries, = struct.unpack_from('<II', data, 48)
        self.contents_hash = str(bytearray(struct.unpack_from("32B", data, 56)))
        self.transf_random_seed = str(bytearray(struct.unpack_from("32B", data, 88)))
        self.key_transf_rounds = struct.unpack_from('<I', data, 120)[0]

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
        elif field_type == 0x0001:
            obj.uuid = uuid.UUID(bytes=field_data)
        elif field_type == 0x0002:
            obj.group_id = struct.unpack_from('<I', field_data)[0]
        elif field_type == 0x0003:
            obj.image = struct.unpack_from('<I', field_data)[0]
        elif field_type == 0x0004:
            obj.title = str(field_data)[:-1]
        elif field_type == 0x0005:
            obj.url = str(field_data)[:-1]
        elif field_type == 0x0006:
            obj.username = str(field_data)[:-1]
        elif field_type == 0x0007:
            obj.password = str(field_data)[:-1]
        elif field_type == 0x0008:
            obj.comment = str(field_data)[:-1]
        elif field_type == 0x0009:
            obj.creation = self._read_date(field_data)
        elif field_type == 0x000A:
            obj.last_mod = self._read_date(field_data)
        elif field_type == 0x000B:
            obj.last_access = self._read_date(field_data)
        elif field_type == 0x000C:
            obj.expire = self._read_date(field_data)
        elif field_type == 0x000D:
            obj.binary_desc = str(field_data)[:-1]
        elif field_type == 0x000E:
            obj.binary = bytearray(field_data)
        elif field_type == 0xFFFF:
            pass
        else:
            return False  # field unsupported

        return True  # field supported

    def _read_date(self, data):
        dw1, dw2, dw3, dw4, dw5 = struct.unpack_from('BBBBB', data)

        y = (dw1 << 6) | (dw2 >> 2)
        mon = ((dw2 & 0x00000003) << 2) | (dw3 >> 6)
        d = (dw3 >> 1) & 0x0000001F
        h = ((dw3 & 0x00000001) << 4) | (dw4 >> 4)
        m = ((dw4 & 0x0000000F) << 2) | (dw5 >> 6)
        s = dw5 & 0x0000003F

        return datetime.datetime(year=y, month=mon, day=d, hour=h, minute=m, second=s)

    def _read_group_field(self, obj, field_type, field_data):
        if field_type == 0x0000:
            # ignore field
            pass
        elif field_type == 0x0001:
            obj.id = struct.unpack_from('<I', field_data)[0]
        elif field_type == 0x0002:
            obj.title = str(field_data)[:-1]
        elif 0x0003 >= field_type <= 0x0006:
            # not longer used by KeePassX but part of the KDB format
            pass
        elif field_type == 0x0007:
            obj.image = struct.unpack_from('<I', field_data)[0]
        elif field_type == 0x0008:
            obj.level = struct.unpack_from('<H', field_data)[0]
        elif field_type == 0x0009:
            # not longer used by KeePassX but part of the KDB format
            pass
        elif field_type == 0xFFFF:
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
        self._header = Header()
        self._header.parse_header(self._data[:Header.DB_HEADER_SIZE])

    def decrypt(self, password):
        raw_master_key = self._get_master_key(password)
        master_key = self._transform(raw_master_key, self._header.transf_random_seed, self._header.key_transf_rounds)
        final_key = utils.sha256([self._header.final_random_seed, master_key])

        if (self._header.cipher == Header.RIJNDAEL_CIPHER):
            cipher = AES.new(final_key, AES.MODE_CBC, self._header.encryption_iv)
            self._unencrypted_data = cipher.decrypt(self._data[Header.DB_HEADER_SIZE:])

            last_byte = struct.unpack_from('B', self._unencrypted_data[-1])[0]
            crypto_size = len(self._data) - last_byte - Header.DB_HEADER_SIZE
        else:
            raise DatabaseException("Unknown encryption algorithm.")

        if crypto_size > 214783446 or (not crypto_size and self.num_groups):
            raise DatabaseException("Decryption failed. The key is wrong or the file is damaged.")

        final_key = utils.sha256(self._unencrypted_data[:crypto_size])

        if self._header.contents_hash != final_key:
            raise DatabaseException("Hash test failed. The key is wrong or the file is damaged.")

    def parse_body(self):
        self.bp = Body(self._unencrypted_data, self._header.num_groups, self._header.num_entries)
        self.bp.parse()

    def get_root_group(self):
        return self.bp.root

    def _transform(self, src, key, rounds):
        kt_left = self._key_transform(src[:16], key, rounds)
        kt_right = self._key_transform(src[16:], key, rounds)

        return utils.sha256(kt_left + kt_right)

    def _key_transform(self, data, key, rounds):
        cipher = AES.new(key, AES.MODE_ECB)

        for i in range(rounds):
            data = cipher.encrypt(data)

        return data

    def _get_master_key(self, pw):
        pw_cp1252 = pw.decode("cp1252")
        return utils.sha256(pw_cp1252)

    def _get_lockfile(self):
        return "{0}.lock".format(self._filename)


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
