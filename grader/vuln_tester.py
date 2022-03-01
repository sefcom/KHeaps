import os
import time
import json
import glob
import tqdm
import traceback
import contextlib
import multiprocessing
from collections import Counter, OrderedDict

from exp_runner import EXPRunner
from utils import path_context, new_logger

KERNEL_SRC = os.path.join("..", "exploit_env", "kernel")

DEFAULT_TEST_NUM = 100
DEFAULT_MAX_RETRY = 20
DEFAULT_TEST_TIMEOUT = 500
DEFAULT_RESULT_FOLDER = "./results"

with open(os.path.join("..", "exploit_env", "setup.conf")) as f:
    config = json.load(f)

@contextlib.contextmanager
def exp_context(args, kwargs):
    exp_runner = None

    # instantiate an exp_runner and try to set it up
    while True:
        try:
            exp_runner = EXPRunner(*args,  **kwargs)
            exp_runner.setup()
            break
        except Exception as e:
            print(e)
            traceback.print_exc()
    yield exp_runner

    # if exp_runner exists, clean it up
    if exp_runner:
        exp_runner.cleanup()

def do_test_once(exp_runner):
    timeout_times = 0
    status = None

    # re-run exp DEFAULT_MAX_RETRY times if the status is "ready"
    for _ in range(DEFAULT_MAX_RETRY):
        try:
            r = exp_runner.run_exp()

            # in case exp_runner fails to run the exp, it is likely the kernel is crashed during launching the exploit
            # so sleep 2 seconds for qemu_runner to detect that
            if r:
                exp_runner.wait_result(r)
                r.close()
                if exp_runner.stress:
                    exp_runner.run_crasher()
            else:
                timeout_times += 1
                time.sleep(2)
            status = exp_runner.qemu.status
            exp_runner.logger.debug("one time status: %s", status)
            if status != 'ready':
                break
            if timeout_times > 15: # this process has been not working for at least 30s
                status = "hang"
                break
        except Exception as e:
            exp_runner.logger.exception(e)
            status = "error"
            break

    if exp_runner.save_log and exp_runner.log_dir:
        exp_runner.save_qemu_output()
    return status

# how one experiment should carry out
def do_test(thing):
    args = thing[0]
    kwargs = thing[1]
    tid = args[0]

    while True:
        with exp_context(args, kwargs) as exp_runner:
            status = do_test_once(exp_runner)
            if status and status not in ["ready", "hang"]:
                break

    exp_runner.logger.info("result: %s", status)
    return tid, status

class VULNTester:
    def __init__(self, cve, test_num=DEFAULT_TEST_NUM, res_dir=DEFAULT_RESULT_FOLDER,
                 save_log=True, fl_rand=False, core_num=2, stress=False, load="both", mem_size=1):
        if cve not in config:
            raise ValueError("Unknown CVE: %s" % cve)
        if os.path.exists(res_dir):
            raise ValueError("result folder exists at {}!!".format(res_dir))

        self.cve = cve
        self.res_dir = res_dir
        self.test_num = test_num
        self.max_runtime = config[cve]["max_runtime"]
        self.save_log = save_log
        self.fl_rand = fl_rand
        self.core_num = core_num
        self.tasks = ["idle", "busy"] if load == 'both' else [load]
        self.stress = stress
        self.mem_size = mem_size

        self.cve_folder = os.path.abspath(os.path.join("..", "exploit_env", "CVEs", cve))
        self.poc_folder = os.path.join(self.cve_folder, "poc")
        self.pool_size = os.cpu_count() // (self.core_num * 2)
        self.pool = multiprocessing.Pool(self.pool_size)
        self.pocs = []

        self.logger = new_logger("VULNTester")

    def make_pocs(self):
        with path_context(self.poc_folder):
            os.system("make clean >/dev/null 2>&1")
            if self.stress:
                os.system("make STRESS=1 >/dev/null 2>&1")
            else:
                os.system("make >/dev/null 2>&1")

        pocs = glob.glob(os.path.join(self.poc_folder, "poc_*"))
        pocs = [os.path.basename(x) for x in pocs if not x.endswith(".c")]
        self.pocs = pocs
        assert self.pocs, "fail to build poc binaries"

    def clean_pocs(self):
        with path_context(self.poc_folder):
            os.system("make clean >/dev/null 2>&1")

    @contextlib.contextmanager
    def poc_ctx(self):
        try:
            self.setup()
            yield
        finally:
            self.cleanup()

    def reset_pool(self):
        self.logger.info("Try to reset pool")
        if self.pool:
            self.logger.info("Try to terminate pool")
            self.pool.close()
            self.pool.terminate()
            self.logger.info("Try to join pool")
            self.pool.join()
        self.logger.info("Try to start a new pool")
        self.pool = multiprocessing.Pool(self.pool_size)

    def _test_poc(self, poc_name, idle=True):

        # prepare input list
        poc_path = os.path.join(self.poc_folder, poc_name)
        args = []
        for i in range(self.test_num):
            dir_name = "%s_%s_%d" % (poc_name, "idle" if idle else "busy", i)
            log_dir = os.path.abspath(os.path.join(self.res_dir, dir_name))
            tmp_arg = [i, poc_path, self.cve_folder]
            tmp_kwargs = {}
            tmp_kwargs['max_runtime'] = self.max_runtime if idle else self.max_runtime*2
            tmp_kwargs['log_dir'] = log_dir
            tmp_kwargs['idle'] = idle
            tmp_kwargs['save_log'] = self.save_log
            tmp_kwargs['fl_rand'] = self.fl_rand
            tmp_kwargs['stress'] = self.stress
            tmp_kwargs['core_num'] = self.core_num
            tmp_kwargs['mem_size'] = self.mem_size
            args.append((tmp_arg, tmp_kwargs))

        # run experiments
        res_map = [None] * len(args)
        it = self.pool.imap_unordered(do_test, args)
        pool_reset_times = 0
        with tqdm.tqdm(total=self.test_num, smoothing=0, dynamic_ncols=True) as pbar:# show progress
            while True:
                try:
                    tid, status = it.next(DEFAULT_TEST_TIMEOUT)
                    res_map[tid] = status
                    pbar.update(1)
                except StopIteration:
                    break
                except multiprocessing.context.TimeoutError:
                    # this is a very bad situation where every worker in the pool is in a very weird state
                    # we reset the pool and continue unfinished experiments
                    self.logger.info("try to reset pool for poc %s!!!", poc_name)
                    self.reset_pool()
                    pool_reset_times += 1
                    if pool_reset_times > 10:
                        for i in range(len(res_map)):
                            if not res_map[i]:
                                res_map[i] = "timeout"
                        break

                    new_args = [args[i] for i in range(len(args)) if res_map[i] is None]
                    it = self.pool.imap_unordered(do_test, new_args)
                    continue
                except Exception as e:
                    self.logger.exception(e)
                    continue

        # process res_map
        res = self._process_result(res_map)

        # save report
        report_path = os.path.join(self.res_dir, "%s_%s_result.json" % (poc_name, "idle" if idle else "busy"))
        with open(report_path, "w") as f:
            json.dump(res, f)

        # process pool may get stuck sometimes, so reset it after each experiment
        self.reset_pool()
        return res

    def _process_result(self, res_map):
        counter = dict(Counter(res_map))

        known_keys = ['success', 'panic', 'timeout', 'error']
        counter['success'] = counter.pop("good_crash", 0)
        counter['panic'] = counter.pop("unknown_crash", 0)
        counter['timeout'] = counter.pop("timeout", 0) + counter.pop("hang", 0)
        counter['error'] = counter.pop("error", 0)

        # ensure ordered keys
        d = OrderedDict()
        for key in known_keys:
            d[key] = counter[key]
        for key in counter.keys():
            if key not in known_keys:
                d[key] = counter[key]
        return d

    def _save_test_poc(self, poc_name, idle=True):
        # sometimes we can trigger some python bugs and the result won't be complete
        # so the solution is to rerun the test if the result is not complete
        d = OrderedDict()
        while True:
            d = self._test_poc(poc_name, idle=idle)
            if sum(d.values()) == self.test_num:
                break
        return d

    def test_pocs(self):
        res = {}
        for poc_name in self.pocs:
            for load in self.tasks:
                # run idle test
                is_idle = load == 'idle'
                ident = "%s_%s" % (poc_name, load)
                self.logger.info("start testing %s...", ident)
                d = self._save_test_poc(poc_name, idle=is_idle)
                res[ident] = d
                self.logger.info(ident)
                self.logger.debug(json.dumps(d, indent=4))
        return res

    def setup(self):
        self.make_pocs()
        os.system("mkdir %s" % self.res_dir)

    def cleanup(self):
        self.clean_pocs()


if __name__ == "__main__":

    import argparse
    # parse arguments
    parser = argparse.ArgumentParser(description='Scripts to evaluate stability of kernel exploits',
                                     usage="%(prog)s [options] -c <CVE number>")
    parser.add_argument('-c', '--cve', type=str, choices=list(config.keys()),
                        help="specify what CVE to test", required=True)
    parser.add_argument('-n', '--num', type=int,
                        help="run how many times for each exploit", default=DEFAULT_TEST_NUM)
    parser.add_argument('-r', '--res-dir', type=str,
                        help="path of the result folder", default=DEFAULT_RESULT_FOLDER)
    parser.add_argument('-nl', '--no-save-log', action="store_true",
                        help="do not save qemu and exploit outputs", default=False)
    parser.add_argument('-fl', '--freelist-random', action="store_true",
                        help="turn on CONFIG_FREELIST_RANDOM, default is False", default=False)
    parser.add_argument('-C', '--core-num', type=int,
                        help="number of cores in the VM", default=2)
    parser.add_argument('-m', '--mem-size', type=int,
                        help="memory used for launching VM (GB)", default=1)
    parser.add_argument('-l', '--load', type=str, choices=["idle", "busy", "both"],
                        help="workload in the target system", default="both")
    parser.add_argument('-s', '--stress', action='store_true',
                        help="run heap-intensive function after each exploit attempt", default=False)
    args = parser.parse_args()

    # tester = VULNTester("CVE-2016-0728", test_num=DEFAULT_TEST_NUM)
    #tester = VULNTester("CVE-2016-0728", test_num=10)
    #tester = VULNTester("CVE-2016-6187", test_num=10)
    tester = VULNTester(args.cve, test_num=args.num, res_dir=args.res_dir,
                        save_log=(not args.no_save_log), fl_rand=args.freelist_random,
                        core_num=args.core_num, load=args.load, stress=args.stress, mem_size=args.mem_size)
    tester.setup()

    tester.logger.debug(tester.test_pocs())

    tester.cleanup()
