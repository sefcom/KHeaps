import re

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def parse(fname):
    with open(fname) as f:
        lines = f.read().splitlines()
    
    records = [x for x in lines if 'kmalloc' in x]
    d = {}
    for record in records:
        res = re.search(f"kmalloc-(\d+): (\d+)", record)
        size = int(res.group(1))
        usage = int(res.group(2))
        d[size] = usage
    return d
d1 = parse("heap_idle_result.txt")
d2 = parse("heap_busy_result.txt")

# plot the graph
keys = sorted(list(d1.keys()))
X = ["kmalloc-%d" % x for x in keys]
Y1 = [d1[x] for x in keys]
Y1 = np.array(Y1)
Y1 = np.log(Y1)
Y2 = [d2[x] for x in keys]
Y2 = np.array(Y2)
Y2 = np.log(Y2)

Y1 = Y1.reshape((Y1.shape[0], 1))
Y2 = Y2.reshape((Y2.shape[0], 1))
Y = np.concatenate([Y1, Y2], axis=1)
Y = pd.DataFrame(Y, columns=["idle", "busy"], index=X)

fig = Y.plot(kind="bar", rot=45, color=["blue", "red"])
fig.set_title("cache vs log(usage)")
#plt.bar(X, [Y1, Y2])
plt.show()

# print the table
line = "%s %s %s" % ("cache_name".ljust(0xc), "idle/s/cpu".rjust(10), "busy/s/cpu".rjust(10))
print(line)
for key in sorted(d1.keys()):
    cache_name = "kmalloc-%d" % key
    #line = cache_name.ljust(0x10, ' ') + str(d1[key]/3600.0) + str(d2[key]/3600.0)
    line = "%s %10.2f %10.2f" % (cache_name.ljust(0xc), d1[key]/3600.0/4, d2[key]/3600.0/4)
    print(line)
