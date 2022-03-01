import json

with open("result.json") as f:
#with open("cpu_busy_result.json") as f:
    data = json.load(f)

line_num = len(data)

total = 0
for record in data:
    total += sum(record[-1])

print(total*1.0/(4*line_num))
