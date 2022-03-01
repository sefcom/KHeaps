# Setup
For the environment setup, we provide a dockerfile to ease the process.

To build the docker image, you need to run the following command in the source code root directory
~~~
cd scripts/create-image/ && ./create-image.sh && cd ../..
docker build -t kheap .
~~~
The command takes around 10 minutes to finish.

At this point, a docker image called `kheap` will be created.

# Evaluation
The evaluation can be done completely inside the `kheap` docker image.

To launch a `kheap` docker container, you should use `docker run --privileged -it kheap bash`. Note that we need the `privileged` flag because the experiments are run in QEMU, which requires the access to kvm to speed up the virtual machines.

Then you can use the following command inside the docker container to evaluate all exploits for a specific CVE
~~~
cd /kheap/grader && python vuln_tester.py -c <cve_number> -n 5000 -r ./results -C 2 -m 2 -nl
~~~
The above command will run exploits for the specific CVE for 5000 times and save the result in `results` folder under 2CPU+2GB RAM setting

For example, `cd /kheap/grader && python vuln_tester.py -c CVE-2010-2959 -n 5000 -r ./results -C 2 -m 2 -nl` will start evaluation for CVE-2010-2959.

For detailed usage, please refer to the help message using `python vuln_tester.py -h`.

When each evaluation finishes, the result will be printed in stdout and also saved in the `results` folder in json format.

Note that a full-fledge 5000-run experiment for one CVE takes a 48-core machine 4-6 days to finish.
