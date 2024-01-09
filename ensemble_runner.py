# Description: Ensemble runner for Cmplog and FOX
# 
# Usage: python3 ensemble_runner.py -i [corpus_dir] -o [output_dir] -b [target_binary] -x [dicts] --fox_target_binary [fox_target_binary] --cmplog_target_binary [cmplog_target_binary]
#
# If fox_target_binary and cmplog_target_binary are not provided, they will be set to [target_binary]_fox and [target_binary]_cmplog respectively
# If dicts are not provided, all .dict files in the current directory will be used
#
# One can also directly import the EnsembleFuzzer class, which can be used as follows:
# EnsembleFuzzer(corpus_dir, output_dir, dicts, target_binary, cmplog_target_binary, fox_target_binary).run()
# 
# Required fuzzer binaries in the current directory (names/paths modifiable in the script, see CMPLOG_FUZZ_BIN_NAME and FOX_FUZZ_BIN_NAME):
#   - fox_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/sbft24_hybrid_mode # sbft24_stable + ~10 added lines
#   - cmplog_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/4.09c_hybrid_mode # 4.09c_baseline (4.09c release) + ~5 added lines
# 
# Required environment variables:
#   - AFL_AUTORESUME: set to 1 (EnsembleFuzzer will set it to 1 if it is not set)
#
# The supported timeout strategies work as follows:
#  - script-side policy: determines the timeout constant for a single fuzzing run (can be changed by modifying TMOUT_STRAT)
#    - const: constant timeout of 2 hours (TMOUT_STRAT_CONST)
#    - geom: geometric timeout, starting at 5 minutes and doubling after each run (TMOUT_STRAT_GEOM_BASE and TMOUT_STRAT_GEOM_MULT)
#
#  - fuzzer-side policy: determines the baseline which to measure the timeout against (can be changed by modifying setting #define TIME_SINCE_START_STRAT)
#    - time-since-last-cov: timeout is measured against the time since the last coverage discovery (no #define TIME_SINCE_START_STRAT)
#    - time-since-start: timeout is measured against the time since the start of the fuzzing run (#define TIME_SINCE_START_STRAT)
#
# The default combination is script-side policy: const, fuzzer-side policy: time-since-start (strat=const-start)
#
# The two combinations I am currently testing are:
# - script-side policy: const, fuzzer-side policy: time-since-start (strat=const-start, expecting binaries with _start suffix and compiled with #define TIME_SINCE_START_STRAT)
# - script-side policy: geom, fuzzer-side policy: time-since-last-cov (strat=geom-cov)
#


import argparse
import fcntl
import glob
import json
import logging
import os
import shutil
import signal
import subprocess
import time

from collections import deque, namedtuple
from typing import List, Deque # breaks with Python >= 3.9, replace with list[str], deque[AFLFuzzer]

# Fuzzer-command specific constants
INT_MAX = '2147483647'
COMMON_ARGS = ['-m', 'none', '-d', '-t', '1000+']
CMPLOG_FUZZ_BIN_NAME = "./cmplog_4.09c_hybrid"
FOX_FUZZ_BIN_NAME = "./fox_4.09c_hybrid"

# Might be needed to remove dangling processes after the fuzzer,
# needs to be verified whether this actually is a problem in the fuzzbench container
# FUZZBENCH_RUN = False

# Timeout strategies
TMOUT_STRAT_GEOM_BASE = 5 * 60 # 5 min
TMOUT_STRAT_GEOM_MULT = 2 # double after each run
TMOUT_STRAT_CONST = 60 * 60 # 1 hour
TMOUT_STRAT = "geom"


Lock = namedtuple('Lock', ['command', 'pid', 'type', 'size', 'mode', 'm', 'start', 'end', 'path'])


def get_locks():
    """Get the current locks."""
    try:
        ret = subprocess.run(['lslocks', '-J'], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        logging.warning("lslocks failed: {e}")
        return []
    except FileNotFoundError as e:
        logging.warning(f"lslocks not found: {e}")
        return []
    return [Lock(**lock) for lock in json.loads(ret)['locks']] if len(ret) > 0 else []


def kill_locking_processes(path: str):
    """Kill any locking processes."""
    killed_processes = set()
    for lock in get_locks():
        try:
            if lock.path and os.path.samefile(lock.path, path) and lock.pid and lock.pid not in killed_processes:
                os.kill(lock.pid, signal.SIGKILL)
                killed_processes.add(lock.pid)
        except OSError as e:
            logging.warning(f"Failed to kill process {lock.pid} corresponding to lock {str(lock)}: {e}")


def unlock_dir(path: str):
    """Unlock the output directory."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        logging.warning(f"Failed to open directory {path}: {e}")
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError as e:
        logging.warning(f"Failed to unlock directory {path}: {e}")
    os.close(fd)


def replace_dir(path: str):
    """Replace the directory with a new one."""
    new_output_dir = path + "_new"
    try:
        shutil.move(path, new_output_dir)
        shutil.move(new_output_dir, path)
    except OSError as e:
        logging.warning(f"Failed to replace output directory: {e}")


def kill_dangling_processes(target_binary: str):
    """Kill any dangling processes. Only used in fuzzbench, where memory usage is limited and each fuzzer runs in isolation."""
    run_command(['pkill', '-9', '-f', f'./{target_binary}'])


def tmout_strat_geom(run_cnt: int):
    """Get the timeout for a run using a geometric strategy."""
    return TMOUT_STRAT_GEOM_BASE * (TMOUT_STRAT_GEOM_MULT ** run_cnt)


def get_cur_time_s():
    """Get the current time in seconds."""
    return int(time.time())


def run_command(command: List[str]):
    """Run a checked command."""
    subprocess.run(command, check=True)


def rmtree_if_exists(dir: str):
    """Remove a directory if it exists."""
    if os.path.exists(dir):
        shutil.rmtree(dir)


# Experimental
def is_inline_table_wrong(target_binary: str, args: List[str]):
    """Check whether the inline table is wrong."""
    os.environ["AFL_DEBUG"] = "1"
    ret = subprocess.run([target_binary] + args, capture_output=True, text=True)
    os.environ["AFL_DEBUG"] = "0"
    num_occ = sum(line.startswith("Running __sanitizer_cov_trace_pc_guard_init: ") for line in ret.stdout.splitlines() + ret.stderr.splitlines())
    return num_occ != 1


class AbstractFuzzer:
    """Abstract class for a fuzzer."""
    name: str
    run_cnt: int
    corpus_dir: str
    output_dir: str
    command: List[str]
    dicts: List[str]
    target_binary: str
    args: List[str]

    def run(self):
        raise NotImplementedError()

    def build_command(self):
        raise NotImplementedError()

    def get_timeout(self):
        raise NotImplementedError()


class AFLFuzzer(AbstractFuzzer):
    """Base class for an AFL fuzzer."""
    timeout: bool
    run_err: Exception

    def __init__(self, name: str, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, args: List[str]):
        self.name = name
        self.run_cnt = 0
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.sync_output_dir = os.path.join(self.output_dir, self.name)
        self.dicts = dicts
        self.target_binary = target_binary
        self.args = args
        self.timeout = False
        self.command = None
        self.run_err = None

    def add_common_args(self):
        """Add the common arguments to the command."""
        if self.timeout:
            self.command += ['-V', str(self.get_timeout())]
        self.command += COMMON_ARGS
        for dict in self.dicts:
            self.command += ['-x', dict]
        self.command += ['-i', self.corpus_dir, '-o', self.output_dir, '-M', self.name, '--', self.target_binary] + self.args + [INT_MAX]

    def do_run(self):
        """Run the fuzzer. If it fails with a CalledProcessError, try to recover. If it fails again, give up."""
        try:
            return run_command(self.command)
        except subprocess.CalledProcessError as e:
            logging.warning(f"Run failed with error {e}, attempting to recover by killing locking processes")
            kill_locking_processes(self.sync_output_dir)
        try:
            return run_command(self.command)
        except subprocess.CalledProcessError as e:
            logging.warning(f"Run failed with error {e}, attempting to recover by unlocking the output directory")
            unlock_dir(self.sync_output_dir)
        try:
            return run_command(self.command)
        except subprocess.CalledProcessError as e:
            logging.warning(f"Run failed with error {e}, attempting to recover by replacing the output directory")
            replace_dir(self.sync_output_dir)
        try:
            return run_command(self.command)
        except subprocess.CalledProcessError as e:
            logging.error(f"Run failed with error {e}, unable to recover")
            self.run_err = e

    def do_run_timed(self):
        """Run the fuzzer, time it, and save the error if it fails."""
        self.time_start = get_cur_time_s()
        try:
            self.do_run()
        except Exception as e:
            logging.error(f"Unexpected error while running the fuzzer")
            logging.exception(e)
            self.run_err = e
        self.time_end = get_cur_time_s()

    def kill_dangling_processes(self):
        kill_dangling_processes(self.target_binary)

    def run(self):
        """Run the fuzzer and log the result."""
        self.build_command()
        self.do_run_timed()
        logging.info(self.get_run_info())
        # if FUZZBENCH_RUN:
            # self.kill_dangling_processes()
        self.run_cnt += 1

    def get_run_info(self):
        """Get the run info as a JSON string."""
        return json.dumps({
            'name': self.name,
            'run_cnt': self.run_cnt,
            'time_start': self.time_start,
            'time_end': self.time_end,
            'command': self.command,
            'run_err': str(self.run_err)
        })

    def get_timeout(self):
        """Get the timeout for a run."""
        if TMOUT_STRAT == "const":
            return TMOUT_STRAT_CONST
        elif TMOUT_STRAT == "geom":
            return tmout_strat_geom(self.run_cnt)
        else:
            raise ValueError(f"Unknown timeout strategy: {TMOUT_STRAT}")


class CmplogFuzzer(AFLFuzzer):
    cmplog_target_binary: str

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str, args: List[str]):
        self.cmplog_target_binary = cmplog_target_binary
        super().__init__("cmplog", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        self.command = [CMPLOG_FUZZ_BIN_NAME, '-c', self.cmplog_target_binary]
        self.add_common_args()


class FoxFuzzer(AFLFuzzer):

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, args: List[str]):
        super().__init__("fox", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        self.command = [FOX_FUZZ_BIN_NAME, '-k', '-p', 'wd_scheduler']
        self.add_common_args()

class EnsembleFuzzer:
    output_dir: str
    fuzzer_queue: Deque[AFLFuzzer]

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str, fox_target_binary: str, args: List[str]):
        self.output_dir = output_dir
        self.fuzzer_queue = deque([
            CmplogFuzzer(corpus_dir, output_dir, dicts, target_binary, cmplog_target_binary, args),
            FoxFuzzer(corpus_dir, output_dir, dicts, fox_target_binary, args)
        ])

    def run(self):
        """Run the fuzzer ensemble. If a fuzzer fails, it is removed from the queue. If one fuzzer remains, it is run without a timeout."""
        os.makedirs(self.output_dir, exist_ok=True)
        while len(self.fuzzer_queue):
            fuzzer = self.fuzzer_queue.popleft()
            fuzzer.timeout = len(self.fuzzer_queue) > 0
            fuzzer.run()
            if fuzzer.run_err is None:
                self.fuzzer_queue.append(fuzzer)
            os.environ["AFL_AUTORESUME"] = "1"
        raise RuntimeError("No fuzzer left in the queue, this should not happen")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--corpus_dir", type=str, required=True, help="Directory containing the corpus")
    parser.add_argument("-o", "--output_dir", type=str, required=True, help="Directory to store output")
    parser.add_argument("-b", "--target_binary", type=str, required=True, help="Path to the vanila AFLplusplus-instrumented target binary")
    parser.add_argument("-a", "--args", type=str, nargs="*", default=[], help="Arguments to pass to the target binary")
    parser.add_argument("-x", "--dicts", type=str, nargs="+", default=None, help="Path to the dictionaries, if not provided, will be set to all .dict files in the current directory")
    parser.add_argument("--fox_target_binary", type=str, default=None, help="Path to the FOX-instrumented target binary, if not provided, will be set to [target_binary]_fox")
    parser.add_argument("--cmplog_target_binary", type=str, default=None, help="Path to the cmplog-instrumented target binary, if not provided, will be set to [target_binary]_cmplog")
    # Experimental
    parser.add_argument("--strat", type=str, default="const-start", choices=["geom-cov", "const-start"], help="Timeout strategy, can be one of: geom-cov, const-start")
    return parser.parse_args()


def main(args):
    if args.cmplog_target_binary is None:
        args.cmplog_target_binary = f"{args.target_binary}_cmplog"
    if args.fox_target_binary is None:
        args.fox_target_binary = f"{args.target_binary}_fox"
    if args.dicts is None:
        args.dicts = glob.glob("*.dict")

    # Experimental
    global TMOUT_STRAT, CMPLOG_FUZZ_BIN_NAME, FOX_FUZZ_BIN_NAME
    if args.strat == "geom-cov":
        TMOUT_STRAT = "geom"
    elif args.strat == "const-start":
        TMOUT_STRAT = "const"
        CMPLOG_FUZZ_BIN_NAME = f"{CMPLOG_FUZZ_BIN_NAME}_start"
        FOX_FUZZ_BIN_NAME = f"{FOX_FUZZ_BIN_NAME}_start"

    os.makedirs(args.output_dir, exist_ok=True)
    logging.basicConfig(filename=os.path.join(args.output_dir, "ensemble_runner.log"), level=logging.DEBUG)

    fuzzer = EnsembleFuzzer(args.corpus_dir, args.output_dir, args.dicts, args.target_binary, args.cmplog_target_binary, args.fox_target_binary, args.args)
    try:
        fuzzer.run()
    except KeyboardInterrupt:
        print("Ending ensemble run")


if __name__ == "__main__":
    main(parse_args())
