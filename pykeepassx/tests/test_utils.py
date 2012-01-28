from pykeepassx.utils import partition, flatten


def test_partition():
    trues, falses = partition(lambda x: x == 1, (1, 2, 3, 1, 2, 3, 1))

    assert len(trues) == 3
    assert len(falses) == 4
    assert trues == [1, 1, 1]
    assert 1 not in falses


def test_flatten():
    assert list(flatten([1, 2])) == [1, 2]
    assert list(flatten([1, "foo"])) == [1, "f", "o", "o"]
    assert list(flatten([1, [2, 3]])) == [1, 2, 3]
    assert list(flatten([[2, 3]])) == [2, 3]
    assert list(flatten([1, "foo", 2, "bar", [3, 4], [5, 6]])) == [1, "f", "o", "o", 2, "b", "a", "r", 3, 4, 5, 6]
