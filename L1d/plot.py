from matplotlib import pyplot as plt

def draw(candidates):
    avg = lambda x:sum(x) / len(x)
    minimum = [min(each) for each in candidates]
    maximum = [max(each) for each in candidates]
    average = [avg(each) for each in candidates]
    rounds = [i for i in range(1, len(candidates) + 1)]

    plt.figure(1)
    plt.plot(rounds, minimum, label="MIN")
    plt.plot(rounds, maximum, label="MAX")
    plt.plot(rounds, average, label="AVG")
    plt.legend()
    plt.xlabel("rounds")
    plt.ylabel("candidates count")

    plt.savefig("draw.png")

if __name__ == '__main__':
    candidates = []
    filename = "data.txt"
    f = open(filename, "r")
    for line in f.readlines():
        if not line:  
            break
        line = line.strip()
        candidates.append([int(each) for each in line.split(' ') if each])
    draw(candidates)
      