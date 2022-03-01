import json
from pwn import *

r = process(["top", "-Hb"])

def get_data():
    cpu_data = r.recvuntil("  PID USER").decode('latin1')
    proc_data = r.recvuntil("top - ").decode('latin1')
    return (cpu_data, proc_data)

def get_cpu_usage(cpu_data):
    data = cpu_data
    records = [ x for x in data.splitlines() if x.startswith('%Cpu')]
    idle_rates = []
    for line in records:
        idle_rate = [x for x in line.split(",") if 'id' in x]
        assert len(idle_rate) == 1
        idle_rates.append(idle_rate[0][:-2])
    for line in records:
        print(line)
    return [100-float(x) for x in idle_rates]

def get_thread_num(proc_data):
    count = 0
    for line in proc_data.splitlines():
        if 'httpd' in line:
            count += 1
    return count

result = []
i = 0
while True:
    try:
        i += 1
        cpu_data, proc_data = get_data()
        cpu_usage = get_cpu_usage(cpu_data)
        thread_num = get_thread_num(proc_data)
        ts = time.time()
        print(ts, thread_num, cpu_usage)
        result.append((ts, thread_num, cpu_usage))
        if i % 10 == 0:
            with open("result.json", "w") as f:
                json.dump(result, f, indent=2)
        print('-'*0x10)
    except Exception:
        pass

r.interactive()
