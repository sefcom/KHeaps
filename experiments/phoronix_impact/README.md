# Overview

This folder contains all the necessary scripts to evaluate the CPU usage and background heap usage in both idle and busy systems.

The idea is to use `top` collect CPU usage and a patched kernel to collect heap usage.

# CPU usage
1. launch an experiment VM by `cd exploit_env/CVEs/CVE-2010-2959; ./startvm` and log in with `root` user (no password)
2. Upload `cpu_measure.py` to the VM by `./copy2vm ../../../experiments/phoronix_impact/cpu_measure.py` inside `exploit_env/CVEs/CVE-2010-2959`
3. run `apt-get install -y python-pip; pip install pwntools pathlib2` in the VM to prepare the environment
4. run `python cpu_measure.py` in the VM and then a `result.json` file will be generated in the VM after 10 seconds. The longer the script keeps running, the more accurate the result will be.
5. use `scp -i ./img/stretch.id_rsa -P 10069 root@localhost:/root/result.json ../../../experiments/phoronix_impact/` in the host
6. `python cpu_calc.py` will output the CPU usage

# Heap usage
prerequisite: a disk image is created in `create-image` already
1. `cd scripts/kernel_builder && ./build_kernel` to build a base kernel first. Use `startvm` to make sure it is runnable
2. `cd kernel && git apply ../../../experiments/phoronix_impact/heap_usage.patch && make -j40` to compile the patched kernel. This process should be fast.
3. This patched kernel has a `/dev/heap_usage` virtual device. `echo 0 > /dev/heap_usage` will clear the heap usage measurement. `cat /dev/heap_usage` will output the heap usage of each kmalloc cache since the last wipe.

