from ubuntu:18.04

run apt-get update
run apt-get install -y qemu-system python3 python3-pip libkeyutils-dev sudo debootstrap openssh-client
run ln -sf /usr/bin/python3 /usr/bin/python
run ln -sf /usr/local/bin/pip3 /usr/local/bin/pip
run pip3 install --upgrade pip
run pip3 install setuptools-rust pwntools

copy . /kheap/
run pip3 install -r /kheap/grader/requirements.txt
run mkdir -p /root/.ssh

cmd bash
