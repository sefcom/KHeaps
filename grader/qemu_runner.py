import os
import time
import threading
import traceback
from pwn import process, context

CRASH_IP = b"deadbeef"
PANIC_BANNER = b"end Kernel panic"
DEFAULT_MAX_READY_TIMEOUT = 60

context.log_level = 'error'

class QEMURunner:
    def __init__(self, ssh_port, cve_folder, timeout=0.1, fl_rand=False, core_num=2, mem_size=1):
        self.kernel = None
        self.fl_rand = fl_rand
        self.core_num = core_num
        self.ssh_port = ssh_port
        self.mem_size = mem_size
        self.status = "dead"
        self.timeout = timeout
        self.output = b''
        self.cve_folder = os.path.abspath(cve_folder)
        self.init_event = threading.Event()
        self.start_ts = None
        os.chdir(cve_folder)

    def launch(self):
        if self.fl_rand:
            self.kernel = process(["./freelist_startvm", str(self.ssh_port), str(self.core_num), "%dG" % self.mem_size])
        else:
            self.kernel = process(["./startvm", str(self.ssh_port), str(self.core_num), "%dG" % self.mem_size])

        self.status = "launching"
        self.start_ts = time.time()

        # launching update thread
        def update_func():
            self.init_event.wait()
            while self.status == 'ready':
                try:
                    self.update()
                    time.sleep(self.timeout)
                except Exception as e:
                    print(e, "handled")
        t = threading.Thread(target=update_func)
        t.start()

    def kill(self):
        self.status = "dead"
        self.kernel.kill()

    @property
    def crashed(self):
        return "crash" in self.status

    def update(self):
        if self.crashed:
            return
        elif self.status == "launching":
            try:
                output = self.kernel.recvuntil(b" login: ", timeout=self.timeout)
                self.output += output
                if b" login: " in output:
                    self.status = "ready"
            except EOFError:
                print("qemu output", self.output)
                raise RuntimeError("fail to launch qemu")
            except Exception as e:
                print("Something wrong with qemu")
                print(e)
                traceback.print_exc()
                raise RuntimeError("Something wrong with qemu")
                #import IPython;IPython.embed()
        elif self.status == "ready":
            try:
                output = self.kernel.recv(timeout=self.timeout)
                self.output += output
            except Exception as e:
                print("Something wrong with qemu")
                print(e)
                traceback.print_exc()
                raise RuntimeError("Something wrong with qemu")
                #import IPython;IPython.embed()

        # check whether the kernel is crashed
        if PANIC_BANNER in self.output:
            # if kernel crashed,
            if CRASH_IP in self.output:
                self.status = "good_crash"
            else:
                self.status = "unknown_crash"

    def save_fingerprint(self):
        ret = os.system("ssh-keygen -F [127.0.0.1]:%d -f ~/.ssh/known_hosts 2>/dev/null 1>/dev/null" % self.ssh_port)
        if ret == 0:
            return
        os.system("ssh-keyscan -t rsa -p %d 127.0.0.1 >> ~/.ssh/known_hosts 2>/dev/null" % self.ssh_port)

    def wait_ready(self, timeout=DEFAULT_MAX_READY_TIMEOUT):
        start = time.time()
        while self.status != "ready":
            self.update()
            time.sleep(self.timeout)
            if time.time() - start > timeout:
                raise RuntimeError("kernel is never ready")
        if b'[\x1b[0;1;31mFAILED\x1b[0m]' in self.output: # this happens to network subsystem often
            #print(self.output.decode())
            raise RuntimeError("kernel failed to initialize")
        self.init_event.set()
        self.save_fingerprint()


if __name__ == '__main__':
    qemu = QEMURunner(1264, cve_folder="../exploit_env/CVEs/CVE-2018-6555", core_num=4, mem_size=2)
    qemu.launch()
    try:
        qemu.wait_ready()
    except RuntimeError:
        print(qemu.output.decode())
        qemu.kernel.interactive()
    print(qemu.output.decode())
    qemu.status = 'dead'
    #os.system("killall -9 qemu-system-x86_64")
    os.system("kill -9 %d" % qemu.kernel.pid)
    #qemu.kill()
