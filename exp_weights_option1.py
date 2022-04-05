import numpy as np
from matplotlib import pyplot as plt
from math import e

def main():
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    colors = ['r', 'g', 'b', 'y', 'c']

    ts = [10, 20, 30, 40, 50] # total number of sectors 
    assert (len(ts) == len(colors))

    for i, t in enumerate(ts):
        x, y = score(t) # x is the number of matched sectors; y is the weighted score; t is total sectors
        plt.plot(x, y, colors[i])

    plt.show()


def score(t, s=1.0, q=2.0):
    x = np.linspace(0, t, t)
    # this is the weighting equation:
    # y = weighted score; x = number of matched sectors; t = total sectors; q adjusts the shape of the curve
    # increasing q prioritizes the first matching sectors (steeper curve)
    # (you can adjust s, but probably don't need to; if so, the equation would have to be modified (it starts at non-zero if s is not 1.0))
    y = (1 - ((1/(x + s))**q))**(np.log(t))
    # print(y) # uncomment this if you want to see values; they should approach 1.00
    return x, y


if __name__ == "__main__":
    main()
