import os
import glob
from contextlib import contextmanager

TARGET_CONFIG = "../bk_config"
TARGET_KERNEL = "kernel"

@contextmanager
def tmp_config(path):
    os.chdir("kernel")
    assert os.path.exists(path)
    os.system("cp %s ./.config" % path)
    try:
        yield
    except:
        os.system("rm .config")

def build_kernel(cve):
    patches = glob.glob(os.path.join("..", "..", '..', 'exploit_env', 'CVEs', cve, "*.patch"))
    target_loc = os.path.join("..", "..", "..", "exploit_env", "CVEs", cve, TARGET_KERNEL)
    target_full_path = os.path.join(target_loc, "arch", "x86", "boot")
    print(target_full_path)
    os.system("mkdir -p %s" % target_full_path)

    assert len(patches) == 1
    patch = patches[0]
    os.system("git checkout .")
    
    os.system("git clean -d -f")
    os.system("git apply ../patches/kernel_patch")
    os.system("git apply %s" % patch)
    os.system("make -j 40")
    os.system("cp %s %s" % ("./vmlinux", target_loc))
    os.system("cp %s %s" % ("./arch/x86/boot/bzImage", target_full_path))

with tmp_config(TARGET_CONFIG):
    cves = [os.path.basename(os.path.dirname(x)) for x in glob.glob(os.path.join("..", "..", "..", "exploit_env", "CVEs", "*", "*.patch"))]
    
    for cve in cves:
        build_kernel(cve)
