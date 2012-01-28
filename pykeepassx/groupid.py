import crypto


_id_set = set()


def new(new_id):
    global _id_set
    _id_set.add(new_id)
    return new_id


def generate():
    global _id_set

    while True:
        new_id = crypto.randomize_int(4)
        if new_id != 0 and not new_id in _id_set:
            return new(new_id)
