import collections
import datetime
import uuid


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
