import hashlib
from Crypto.Cipher import AES
import Crypto.Random
import Crypto.Util.number
import struct


def randomize(length):
    return Crypto.Random.get_random_bytes(length)


def randomize_int(length, maximum=None):
    i = Crypto.Util.number.getRandomInteger(length * 8)
    return i if not maximum else i % maximum


def sha256(lst):
    m = hashlib.sha256()

    if isinstance(lst, basestring):
        m.update(lst)
    else:
        for i in lst:
            m.update(i)
    return m.digest()


def decrypt_aes(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data)
    pad_len = struct.unpack('<B', decrypted_data[-1])[0]

    return decrypted_data[:-pad_len]


def key_transform(key, rounds, data):
    cipher = AES.new(key, AES.MODE_ECB)

    for i in range(rounds):
        data = cipher.encrypt(data)

    return data


def transform(src, key, rounds):
    kt_left = key_transform(key, rounds, src[:16])
    kt_right = key_transform(key, rounds, src[16:])

    return sha256(kt_left + kt_right)


def encrypt(data, final_key, iv):
    data = add_padding(data)

    cipher = AES.new(final_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def add_padding(s):
    part_size = (len(s) / 16 + 1) * 16
    pad_len = part_size - len(s)

    data = bytearray(s)

    for i in range(pad_len):
        # Pad lenght is read from the last byte, use pad length as the pad
        data.append(pad_len)

    return str(data)
