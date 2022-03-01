import os
import sys
from pwn import *

if len(sys.argv) != 3:
    print(sys.argv)
    print("this script should be run liket this: python <script_path> <kernel_path> <image_path>")
    exit()

kernel = sys.argv[1]
img = sys.argv[2]
cmd = [ "qemu-system-x86_64",
        "-kernel", kernel,
        "-hda", img,
        "-append", "console=ttyS0 root=/dev/sda debug earlyprintk=serial oops=panic panic_on_warn=1 nokaslr nosmap nosmep",
        "-net", "nic",
        "-net", "user,hostfwd=tcp::4444-:22",
        "-nographic",
        "-m", "1G",
        "-monitor", "none,server,nowait,nodelay,reconnect=-1",
        "-smp", "cores=2,threads=2",
        "-enable-kvm",
        "-cpu", "host,-smap,-smep"
        ]
print(' '.join(cmd))

r = process(cmd)
r.sendlineafter(b" login: ", b"root")

# enable network communication
r.sendlineafter(b":~# ", b"apt-get update")
r.recvuntil(b"root@")
r.sendlineafter(b":~# ", b"sed -i 's/<NoNetworkCommunication>TRUE<\/NoNetworkCommunication>/<NoNetworkCommunication>FALSE<\/NoNetworkCommunication>/g' /etc/phoronix-test-suite.xml")
r.recvuntil(b"root@")
r.sendlineafter(b":~# ", b"sed -i 's/<NoInternetCommunication>TRUE<\/NoInternetCommunication>/<NoInternetCommunication>FALSE<\/NoInternetCommunication>/g' /etc/phoronix-test-suite.xml")
r.recvuntil(b"root@")

# cleanup
r.sendlineafter(b":~# ", b"rm -rf /var/lib/phoronix-test-suite/installed-tests/pts/")
r.recvuntil(b"root@")

# force reinstall apache test
r.sendlineafter(b":~# ", b"phoronix-test-suite install pts/apache-1.7.2")
r.recvuntil(b"root@")

# make download cache
r.sendlineafter(b":~# ", b"phoronix-test-suite make-download-cache")
r.recvuntil(b"root@")

# disable network communication
r.sendlineafter(b":~# ", b"sed -i 's/<NoNetworkCommunication>FALSE<\/NoNetworkCommunication>/<NoNetworkCommunication>TRUE<\/NoNetworkCommunication>/g' /etc/phoronix-test-suite.xml")
r.recvuntil(b"root@")
r.sendlineafter(b":~# ", b"sed -i 's/<NoInternetCommunication>FALSE<\/NoInternetCommunication>/<NoInternetCommunication>TRUE<\/NoInternetCommunication>/g' /etc/phoronix-test-suite.xml")
r.recvuntil(b"root@")

# make sure everything is saved
r.sendlineafter(b":~# ", b"sync")
r.recvuntil(b"root@")

# shutdown
r.sendlineafter(b":~# ", b"exit")
r.shutdown()
