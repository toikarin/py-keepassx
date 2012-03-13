import uuid
import struct
import datetime
import os

import utils
import crypto
import groupid


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

    def __init__(self, uuid=None, group_id=None, image=None, title=None, url=None,
            username=None, password=None, comment=None, creation=None, last_mod=None,
            last_access=None, expire=None, binary_desc=None, binary=None, parent=None):
        self.uuid = uuid
        self.group_id = group_id
        self.image = image
        self.title = title
        self.url = url
        self.username = username
        self.password = password
        self.comment = comment
        self.creation = creation
        self.last_mod = last_mod
        self.last_access = last_access
        self.expire = expire
        self.binary_desc = binary_desc
        self.binary = binary

        self._parent = parent

    def dump(self):
        s = ("[Entry: {0.uuid}: [title: '{0.title}', group_id: {0.group_id}, image: {0.image}, "
             "username: '{0.username}' url: '{0.url}', comment: '{0.comment}', password: {password}, "
             "creation: {0.creation}, last_access: {0.last_access}, last_mod: {0.last_mod}, "
             "expire: {0.expire}, binary_desc: '{0.binary_desc}'.")

        return s.format(self, password="*****" if self.password else '')

    def is_valid(self):
        return (self.uuid
            and self.group_id
            and self.image is not None
            and self.title
            and self.creation
            and self.last_mod
            and self.last_access)

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

    def accessed(self):
        self.last_access = utils.now()

    def updated(self):
        self.last_mod = utils.now()

    def expired(self):
        if self.expire:
            return utils.now() >= self.expire

        return False

    def remove(self):
        if not self._parent:
            return

        self._parent.remove_entry(self)

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
            Entry.FIELD_TYPE_END, 0,
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

    def __init__(self, group_id=None, title=None, creation=None, last_mod=None,
                 last_access=None, expire=None, image=None, level=None, parent=None):
        self.group_id = group_id
        self.title = title
        self.image = image
        self.level = level

        self.creation = None  # unused
        self.last_mod = None  # unused
        self.last_access = None  # unused
        self.expire = None  # unused
        self.flags = 0  # unused

        self._children = list()
        self._entries = list()
        self._parent = parent

    def dump(self):
        s = "[Group: {0.group_id}: [title: '{0.title}', image: {0.image}, level: {0.level}]"
        return s.format(self)

    def is_valid(self):
        return (self.title
            and self.group_id
            and self.image is not None
            and self.level is not None)

    def add_group(self, title):
        """
        Creates a new group and adds it to this group.

        `title` is the title for the new group. It can't be None or empty string.

        Returns the created group.
        """

        if not title:
            raise ValueError("title is not set.")

        now = utils.now()

        initargs = {
            'group_id': groupid.generate(),
            'title': title,
            'creation': now,
            'last_mod': now,
            'last_access': now,
            'image': 1,
            'level': self.level + 1,
            'parent': self,
        }

        group = Group(**initargs)
        self._children.append(group)
        return group

    def get_groups(self):
        """
        Returns the list of groups this group currently has.
        """
        return self._children[:]

    def remove_group(self, group):
        """
        Remove `group` from this group. It is an error if group doesn't belong to this gorup.
        """
        self._children.remove(group)

    def add_entry(self, title, **kwargs):
        """
        Add an new entry to this group.

        `title` is the title for the new entry. It can't be None or empty string.
        `kwargs` can contain following keys:
        url -- Optional URL for the new entry
        username -- Username for the new entry
        password -- Password for the new entry
        comment -- Comment string for the new entry
        expire -- datetime when the entry/password is going to be expire

        Returns the created entry.
        """

        if not title:
            raise ValueError("Title can't be empty.")

        allowed_keys = ("url", "username", "password", "comment", "expire",)

        if set(kwargs.keys()) - set(allowed_keys):
            raise ValueError("Unallowed keys in kwargs.")

        now = utils.now()

        initargs = {
            'title': title,
            'uuid': uuid.uuid1(),
            'parent': self,
            'group_id': self.group_id,
            'image': 1,
            'title': title,
            'creation': now,
            'last_mod': now,
            'last_access': now,
        }

        initargs.update(kwargs)

        entry = Entry(**initargs)
        self._entries.append(entry)
        return entry

    def get_entries(self, include_meta_entries=False):
        """
        Returns the list of entries this group currently has.
        """
        if include_meta_entries:
            return self._entries[:]
        else:
            return filter(lambda x: not x.is_meta_stream(), self._entries)

    def get_meta_entries(self):
        """
        Returns the list of meta entries this group currently has.
        """
        return filter(lambda x: x.is_meta_stream(), self._entries)

    def remove_entry(self, entry):
        """
        Remove `entry` from this group. It is an error if entry doesn't belong to this gorup.
        """
        self._entries.remove(entry)

    def remove(self):
        """
        Remove this group.

        If this group is already removed, nothing happens.
        """
        if not self._parent:
            return

        self._parent.remove_group(self)
        self._parent = None

    def move_entry(self, entry):
        """
        Move `entry` to this group.
        """
        if entry._parent:
            if entry._parent == self:
                raise ValueError("Entry is already in this group.")
            entry._parent.remove_entry(entry)

        entry._parent = self
        self._entries.append(entry)

    def move_group(self, group):
        """
        Move `group` to this group.
        """
        if group == self:
            raise ValueError("Group == self.")

        if group._parent:
            if group._parent == self:
                raise ValueError("Group is already in this group.")
            group._parent.remove_group(group)

        group._parent = self
        _adjust_level(group, self.level + 1)
        self._children.append(group)

    def is_root(self):
        """
        Is this a root group?
        """
        return False

    def to_bytearray(self):
        data = (
            Group.FIELD_TYPE_ID, 4, self.group_id,
            Group.FIELD_TYPE_TITLE, xstr(self.title),
            Group.FIELD_TYPE_CREATION, 5, from_datetime(self.creation),
            Group.FIELD_TYPE_LAST_MOD, 5, from_datetime(self.last_mod),
            Group.FIELD_TYPE_LAST_ACCESS, 5, from_datetime(self.last_access),
            Group.FIELD_TYPE_EXPIRE, 5, from_datetime(self.expire),
            Group.FIELD_TYPE_IMAGE, 4, self.image,
            Group.FIELD_TYPE_LEVEL, 2, self.level,
            Group.FIELD_TYPE_FLAGS, 4, self.flags,
            Group.FIELD_TYPE_END, 0,
        )

        pack_fmt = '<HII HI{title_len}B HI5B HI5B HI5B HI5B HII HIH HII HI'.format(
            title_len=xlen(self.title),
        )

        return struct.pack(pack_fmt, *utils.flatten(data))


class RootGroup(Group):
    def __init__(self):

        initargs = {
            'level': -1,  # -1 so rootgroup.level + 1 == 0 which is the smallest level
        }

        super(RootGroup, self).__init__(**initargs)

    def add_entry(self, title, **kwargs):
        raise ValueError("Root group can't contain any entries.")

    def get_entries(self):
        raise ValueError("Root group can't contain any entries.")

    def remove_entry(self, entry):
        raise ValueError("Root group can't contain any entries.")

    def move_entry(self, entry):
        raise ValueError("Root group can't contain any entries.")

    def remove(self):
        raise ValueError("Root group can't be removed.")

    def is_root(self):
        return True

    def get_groups_and_entries(self):
        entries = list()
        groups = list()

        for g in self.get_groups():
            groups.append(g)
            self._get_groups_and_entries(g, groups, entries)

        return groups, entries

    def _get_groups_and_entries(self, group, groups, entries):
        entries.extend(group.get_entries(include_meta_entries=True))

        for g in group.get_groups():
            groups.append(g)
            self._get_groups_and_entries(g, groups, entries)

    def parse(self, data, num_groups, num_entries):
        groups, pos = self._generic_parse(data, Group, num_groups, 0, self._read_group_field)
        entries, _ = self._generic_parse(data, Entry, num_entries, pos, self._read_entry_field)

        for g in groups:
            if not g.is_valid():
                raise DatabaseException("Invalid group {0}.".format(g.dump()))

        for e in entries:
            if not e.is_valid():
                raise DatabaseException("Invalid entry {0}.".format(e.dump()))

        self._create_group_tree(groups)
        self._map_entries_to_groups(groups, entries)

        return self

    def _map_entries_to_groups(self, groups, entries):
        def get_group(groups, group_id):
            for g in groups:
                if g.group_id == group_id:
                    return g

        for e in entries:
            g = get_group(groups, e.group_id)
            if not g:
                raise DatabaseException("Unable to find group by id {0}".format(e.group_id))

            g.move_entry(e)

    def _create_group_tree(self, groups):
        num_groups = len(groups)

        for i in range(num_groups):
            if groups[i].level == 0:
                self.move_group(groups[i])
            else:
                parent = None
                for j in reversed(range(i)):
                    if groups[j].level == groups[i].level - 1:
                        parent = groups[j]
                        break

                if not parent:
                    raise DatabaseException("Unable to find parent for group {0}".format(groups[i].group_id))

                parent.move_group(groups[i])

    def _generic_parse(self, data, cls, num_entries, pos, func):
        cur_entry = 0
        cur_obj = cls()
        entries = list()
        data_len = len(data)

        while cur_entry < num_entries:
            if pos + 6 > data_len:
                raise DatabaseException("EOF")

            field_type, field_size = struct.unpack_from("<HI", data[pos:])
            pos += 6

            if pos + field_size > data_len:
                raise DatabaseException("EOF")

            retval = func(cur_obj, field_type, data[pos:pos + field_size])

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
            obj.group_id = struct.unpack_from('<I', field_data)[0]
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
    def __init__(self):
        self._header = None
        self._root = RootGroup()

    def get_root_group(self):
        return self._root

    def read(self, data, password):
        self._header = self._parse_header(data)
        decrypted_data = self._decrypt(self._header, data, password)
        self._root = self._parse_body(self._header, decrypted_data)
        return self._root

    def serialize(self, password):
        if not self._header:
            self._header = Header()
            self._header.transf_random_seed = crypto.randomize(32)
            self._header.key_transf_rounds = 50000

        return self._serialize_data(self._root, self._header, password)

    @staticmethod
    def _serialize_data(root, header, password):
        groups, entries = root.get_groups_and_entries()

        # Update header
        header.num_groups = len(groups)
        header.num_entries = len(entries)
        header.final_random_seed = crypto.randomize(16)
        header.encryption_iv = crypto.randomize(16)

        # Generate body
        body = str()

        for g in groups:
            body += g.to_bytearray()

        for e in entries:
            body += e.to_bytearray()

        # Calculate hash from the body
        header.contents_hash = crypto.sha256(body)

        # Encrypt body
        encrypted = crypto.encrypt(body, Database._generate_key(header, password), header.encryption_iv)

        # Generate file content
        data = str()
        data += header.to_bytearray()
        data += encrypted

        return data

    @staticmethod
    def _parse_header(data):
        if len(data) < Header.DB_HEADER_SIZE:
            raise DatabaseException("Unexpected file size (DB_TOTAL_SIZE < DB_HEADER_SIZE)")

        return Header(data[:Header.DB_HEADER_SIZE])

    @staticmethod
    def _decrypt(header, data, password):
        final_key = Database._generate_key(header, password)

        if (header.cipher == Header.RIJNDAEL_CIPHER):
            decrypted_data = crypto.decrypt_aes(final_key, header.encryption_iv, data[Header.DB_HEADER_SIZE:])

            crypto_size = len(decrypted_data)
        else:
            raise DatabaseException("Unknown encryption algorithm.")

        if crypto_size > 214783446 or (not crypto_size and header.num_groups):
            raise DatabaseException("Decryption failed. The key is wrong or the file is damaged.")

        contents_hash = crypto.sha256(decrypted_data[:crypto_size])

        if header.contents_hash != contents_hash:
            raise DatabaseException("Hash test failed. The key is wrong or the file is damaged.")

        return decrypted_data

    @staticmethod
    def _parse_body(header, decrypted_data):
        return RootGroup().parse(decrypted_data, header.num_groups, header.num_entries)

    @staticmethod
    def _generate_key(header, password):
        raw_master_key = Database._get_master_key(password)
        master_key = crypto.transform(raw_master_key, header.transf_random_seed, header.key_transf_rounds)
        return crypto.sha256([header.final_random_seed, master_key])

    @staticmethod
    def _get_master_key(pw):
        pw_cp1252 = pw.decode("cp1252")
        return crypto.sha256(pw_cp1252)


class FSDatabase(Database):
    def __init__(self, filename):
        if not filename:
            raise ValueError("filename can't be empty or None.")

        self._filename = filename

        super(FSDatabase, self).__init__()

    def _read(self, filename):
        raise NotImplementedError

    def _write(self, filename, data):
        raise NotImplementedError

    def _exists(self, filename):
        raise NotImplementedError

    def _unlink(self, filename):
        raise NotImplementedError

    def _rename(self, filename, newfilename):
        raise NotImplementedError

    def _touch(self, filename):
        raise NotImplementedError

    def is_locked(self):
        return self._exists(self._get_lockfile())

    def lock(self):
        pass
        if self.is_locked():
            return

        self._touch(self._get_lockfile())

    def unlock(self):
        if not self.is_locked():
            return

        try:
            self._unlink(self._get_lockfile())
        except Exception as e:
            raise DatabaseException("Error occurred while unlocking.", e)

    def open(self, password):
        try:
            data = self._read(self._filename)
        except IOError as e:
            raise DatabaseException(e)

        return self.read(data, password)

    def save(self, password):
        data = self.serialize(password)

        if self._exists(self._filename):
            tmp = self._filename + ".tmp"
            backup = self._filename + ".bak"

            self._write(tmp, data)

            self._rename(self._filename, backup)
            self._rename(tmp, self._filename)

            if False:  # FIXME
                self._unlink(backup)
        else:
            self._write(self._filename, data)

    def _get_lockfile(self):
        return "{0}.lock".format(self._filename)


class FileDatabase(FSDatabase):
    def __init__(self, filename):
        super(FileDatabase, self).__init__(filename)

    def _read(self, filename):
        with open(filename, "rb") as f:
            return f.read()

    def _write(self, filename, data):
        with open(filename, 'wb') as f:
            f.write(data)

    def _exists(self, filename):
        return os.path.exists(filename)

    def _unlink(self, filename):
        os.unlink(filename)

    def _rename(self, filename, newfilename):
        os.rename(filename, newfilename)

    def _touch(self, filename):
        with open(filename, 'a'):
            pass


class SSHDatabase(FSDatabase):
    def __init__(self, ssh, filename):
        self.ssh = ssh
        super(SSHDatabase, self).__init__(filename)

    def _read(self, filename):
        return self.ssh.read(filename)

    def _write(self, filename, data):
        self.ssh.write(filename, data)

    def _exists(self, filename):
        return self.ssh.exists(filename)

    def _unlink(self, filename):
        return self.ssh.remove(filename)

    def _rename(self, filename, newfilename):
        return self.ssh.rename(filename, newfilename)

    def _touch(self, filename):
        self.ssh.write(filename, '')


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
        return _from_datetime(2999, 12, 28, 23, 59, 59)
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

    if y == 2999 and mon == 12 and d == 28 and h == 23 and m == 59 and s == 59:
        return None

    return datetime.datetime(year=y, month=mon, day=d, hour=h, minute=m, second=s)


def _adjust_level(group, level):
    group.level = level

    for subgroup in group._children:
        _adjust_level(subgroup, level + 1)
