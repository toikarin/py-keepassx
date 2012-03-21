import collections
import datetime
import uuid
import crypto


def now():
    return datetime.datetime.now().replace(microsecond=0)


def generate_uuid():
    return uuid.uuid4()


def partition(pred, iterables):
    trues = list()
    falses = list()

    for i in iterables:
        if pred(i):
            trues.append(i)
        else:
            falses.append(i)

    return trues, falses


def flatten(l):
    for e in l:
        if isinstance(e, basestring):
            for ce in e:
                yield ce
        elif isinstance(e, collections.Iterable):
            for ce in flatten(e):
                yield ce
        else:
            yield e


def generate_password(length, lowercase=True, uppercase=True, numeric=True, special=True, whitespace=True, dash=True,
        underscore=True):
    chars = list()

    if lowercase:
        chars.extend(xrange(65, 90 + 1))

    if uppercase:
        chars.extend(xrange(97, 122 + 1))

    if numeric:
        chars.extend(xrange(48, 57 + 1))

    if special:
        chars.extend(xrange(33, 47 + 1))
        chars.extend(xrange(58, 64 + 1))
        chars.extend(xrange(91, 96 + 1))
        chars.extend(xrange(123, 126 + 1))

    if whitespace:
        chars.append(32)

    if dash:
        chars.append(45)

    if underscore:
        chars.append(95)

    password = ""

    for i in range(length):
        password += chr(chars[crypto.randomize_int(4, len(chars))])

    return password


def copy_to_clipboard(s):
    # FIXME: better error handling (don't fail silently)
    # FIXME: don't depend on xsel
    import subprocess

    try:
        xsel_proc = subprocess.Popen(['xsel', '-pi'], stdin=subprocess.PIPE)
        xsel_proc.communicate(s)

        xsel_proc = subprocess.Popen(['xsel', '-bi'], stdin=subprocess.PIPE)
        xsel_proc.communicate(s)
    except OSError:
        pass
