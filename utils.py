

def partition(pred, iterables):
    trues = list()
    falses = list()

    for i in iterables:
        if pred(i):
            trues.append(i)
        else:
            falses.append(i)

    return trues, falses




def print_group_tree(group, level=0):
    print("{indent}***[{title}]***".format(indent=" " * level, title=group.title))
    for e in group.entries:
        print("{indent}-{title}".format(level=" " * (level + 2), title=e.title))
    for g in group.children:
        print_group_tree(g, level + 4)
