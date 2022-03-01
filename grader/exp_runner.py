import os
import time
import glob
import socket
import signal
import logging

from pwn import ssh

from qemu_runner import QEMURunner
from utils import new_logger, logger_formatter

# Configuration
IP = '127.0.0.1'
USERNAME = 'root'
REMOTE_EXP_PATH = "/tmp/exp"
REMOTE_CRASHER_PATH = "/tmp/crasher"
WORKLOAD_CMD = "while true; do phoronix-test-suite batch-benchmark apache-1.7.2; done"
DEFAULT_MAX_RUNTIME = 60
DIRNAME = os.path.dirname(os.path.abspath(__file__))
LOCAL_CRASHER_PATH = os.path.join(DIRNAME, "..", "exploit_env", "crasher")

def handler(signum, frame):
    raise Exception("Time up!")
signal.signal(signal.SIGALRM, handler)

class EXPRunner:
    def __init__(self, rid, exp_path, cve_folder, max_runtime=DEFAULT_MAX_RUNTIME, save_log=True,
                log_dir=None, idle=True, fl_rand=False, core_num=2, mem_size=1, stress=False):
        self.ssh_port = None
        self.exp_path = os.path.abspath(exp_path)
        self.cve_folder = cve_folder
        self.max_runtime = max_runtime
        self.rid = rid
        self.log_dir = log_dir
        self.idle = idle
        self.save_log = save_log
        self.fl_rand = fl_rand
        self.stress = stress
        self.core_num = core_num
        self.mem_size = mem_size

        self.qemu = None
        self.ssh = None
        self.key = None
        self.run_time = 0

        # setup logger
        self.logger = new_logger("EXPRunner-%d" % rid, level="INFO")
        if log_dir is not None:
            os.system("mkdir -p %s" % log_dir)
            log_path = os.path.join(log_dir, "%d.log" % rid)
            handler = logging.FileHandler(log_path, mode='a', delay=False)
            handler.setLevel("DEBUG")
            handler.setFormatter(logger_formatter)
            self.logger.addHandler(handler)

        self._resolve_key()

        # make sure we are in the correct setup directory
        os.chdir(cve_folder)

    def _resolve_key(self):
        glob_fmt = os.path.join(self.cve_folder, "img", "*.id_rsa")
        res = glob.glob(glob_fmt)
        if not res:
            self.logger.error("fail to find key by glob rule: %s", glob_fmt)
        self.key = res[0]

    def connect(self):
        self.logger.debug("Connecting ssh...")
        try:
            self.ssh = ssh(user=USERNAME, host=IP, port=self.ssh_port, keyfile=self.key)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False

    def upload_exp(self, path):
        self.logger.debug("Uploading exp...")
        self.ssh.upload(self.exp_path, path)
        r = self.ssh.run('chmod u+x "%s"' % path)
        r.wait()

    def upload_crasher(self, path):
        self.logger.debug("Uploading crasher...")

        self.ssh.upload(LOCAL_CRASHER_PATH, path)
        r = self.ssh.run('chmod u+x "%s"' % path)
        r.wait()

    def run_exp(self):
        self.logger.debug("Running exp...")
        self.run_time += 1

        r = None
        signal.alarm(5)
        try:
            r = self.ssh.process([REMOTE_EXP_PATH, str(self.run_time)])
        except Exception as e:
            self.logger.info(e)
        signal.alarm(0)
        return r

    def run_crasher(self):
        self.logger.debug("Running crasher...")

        r = None
        signal.alarm(5)
        try:
            r = self.ssh.process([REMOTE_CRASHER_PATH, str(self.run_time)])
        except Exception as e:
            self.logger.info(e)
        signal.alarm(0)
        return r

    def run_workload(self):
        self.logger.debug("Running workload...")
        r = self.ssh.process(WORKLOAD_CMD, shell=True)

        # make sure workload start running
        r.recvuntil(b"Running Pre-Test Script", timeout=60)
        output = r.recvuntil(b"Started Run", timeout=60)
        if b"Started Run" not in output:
            r.close()
            return None
        time.sleep(3)
        return r

    def wait_result(self, r):
        self.logger.debug("Waiting for exp result...")
        start = time.time()
        output = b""
        while not self.qemu.crashed and time.time() - start < self.max_runtime:
            try:
                output += r.recv(timeout=0.5)
            except EOFError:
                break
        if time.time() - start >= self.max_runtime:
            self.logger.warning("Time out! Killing qemu!")
        if not self.qemu.crashed and r.poll() is None:
            r.kill()
        if self.save_log and self.log_dir:
            self.save_exp_output(output)

    def save_qemu_output(self):
        self.logger.debug("Saving QEMU output...")
        with open(os.path.join(self.log_dir, "qemu_output.txt"), "ab") as f:
            f.write(self.qemu.output)

    def save_exp_output(self, output):
        self.logger.debug("Saving EXP output...")
        with open(os.path.join(self.log_dir, "exp_output.txt"), "ab") as f:
            f.write(output)

    def setup(self):
        self.logger.debug("Setting up...")
        for i in range(5):
            try:
                self.ssh_port = self.get_open_port()
                self.qemu = QEMURunner(self.ssh_port, self.cve_folder, fl_rand=self.fl_rand,
                                       core_num=self.core_num, mem_size=self.mem_size)
                self.qemu.launch()
                self.qemu.wait_ready()
                if self.connect():
                    break
            except RuntimeError as e:
                if self.qemu:
                    self.cleanup()
                self.logger.exception(e)
            self.logger.warning("Setting up EXP environment fails... retry... %d", i)
        else:
            raise RuntimeError("Fail to launch qemu")

        # make sure we have ssh connection
        if not self.ssh:
            raise RuntimeError("Fail to connect ssh")

        self.upload_exp(REMOTE_EXP_PATH)
        # self.upload_crasher(REMOTE_CRASHER_PATH)
        if not self.idle:
            if not self.run_workload():
                raise RuntimeError("Fail to start workload")

    def cleanup(self):
        self.logger.debug("Cleaning up...")
        self.qemu.kill()
        self.qemu = None

    @staticmethod
    def get_open_port():
        """
        get a random open port
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port

if __name__ == '__main__':
    exp_path = os.path.abspath("../exploit_env/CVEs/CVE-2018-6555/poc/poc_cfh_combo")
    cve_folder = os.path.abspath("../exploit_env/CVEs/CVE-2018-6555")
    if not os.path.exists(exp_path):
        print(f"this test requires {exp_path}")
        exit()
    exp_runner = EXPRunner(1, exp_path, cve_folder, core_num=3, mem_size=2)
    exp_runner.setup()
    print(exp_runner.ssh_port)
    # import IPython; IPython.embed()
    r = exp_runner.run_exp()
    exp_runner.wait_result(r)
    print(exp_runner.qemu.status)
    print(exp_runner.qemu.output.decode())
    exp_runner.cleanup()
