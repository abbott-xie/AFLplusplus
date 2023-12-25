# Description: Ensemble runner for Cmplog and FOX
# 
# Usage: python3 ensemble_runner.py -i [corpus_dir] -o [output_dir] -b [target_binary] -x [dicts] --fox_target_binary [fox_target_binary] --cmplog_target_binary [cmplog_target_binary]
#
# If fox_target_binary and cmplog_target_binary are not provided, they will be set to [target_binary]_fox and [target_binary]_cmplog respectively
# If dicts are not provided, all .dict files in the current directory will be used
#
# The script uses only standard Python 3 libraries, so it should work on any system with Python 3 installed
# One can also directly import the EnsembleFuzzer class, which can be used as follows:
# EnsembleFuzzer(corpus_dir, output_dir, dicts, target_binary, cmplog_target_binary, fox_target_binary).run()
# 
# Required fuzzer binaries in the current directory (names/paths modifiable in the script, see CMPLOG_FUZZ_BIN_NAME and FOX_FUZZ_BIN_NAME):
#   - fox_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/sbft24_hybrid_mode
#   - cmplog_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/4.09c_hybrid_mode
# 
# Required environment variables:
#   - AFL_AUTORESUME: set to 1 (EnsembleFuzzer will set it to 1 if it is not set)
#
# The supported timeout strategies work as follows:
#  - script-side policy: determines the timeout constant for a single fuzzing run (can be changed by modifying TMOUT_STRAT)
#    - const: constant timeout of 2 hours (TMOUT_STRAT_CONST)
#    - geom: geometric timeout, starting at 5 minutes and doubling after each run (TMOUT_STRAT_GEOM_BASE and TMOUT_STRAT_GEOM_MULT)
#
#  - fuzzer-side policy: determines the baseline which to measure the timeout against (can be changed by modifying setting #define TIME_SINCE_START)
#    - time-since-last-cov: timeout is measured against the time since the last coverage discovery (no #define TIME_SINCE_START)
#    - time-since-start: timeout is measured against the time since the start of the fuzzing run (#define TIME_SINCE_START)
#
# The default combination is script-side policy: geom, fuzzer-side policy: time-since-last-cov
#


import argparse
import glob
import os
import shutil
import subprocess
import time

from typing import List

# Fuzzer-command specific constants
INT_MAX = '2147483647'
COMMON_ARGS = ['-m', 'none', '-d', '-t', '1000+']
CMPLOG_FUZZ_BIN_NAME = "./cmplog_4.09c_hybrid"
FOX_FUZZ_BIN_NAME = "./fox_4.09c_hybrid"

# Might be needed to remove dangling processes after the fuzzer,
# needs to be verified whether this actually is a problem in the fuzzbench container
FUZZBENCH_RUN = False

# Timeout strategies
TMOUT_STRAT_GEOM_BASE = 5 * 60 # 5 min
TMOUT_STRAT_GEOM_MULT = 2
TMOUT_STRAT_CONST = 2 * 60 * 60 # 2 hours
TMOUT_STRAT = "geom"


def kill_dangling_processes(target_binary: str):
    """Kill any dangling processes. Only used in fuzzbench, where memory usage is limited and each fuzzer runs in isolation."""
    run_command(['pkill', '-9', '-f', f'./{target_binary}'])


def tmout_strat_geom(run_cnt: int):
    """Get the timeout for a run using a geometric strategy."""
    return TMOUT_STRAT_GEOM_BASE * (TMOUT_STRAT_GEOM_MULT ** run_cnt)


def get_cur_time_ms():
    """Get the current time in milliseconds."""
    return int(time.time() * 1000)


def run_command(command: List[str]):
    """Run a command with a timeout."""
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Error running "{" ".join(command)}": {e}')


def rmtree_if_exists(dir: str):
    """Remove a directory if it exists."""
    if os.path.exists(dir):
        shutil.rmtree(dir)


def force_afl_autoresume():
    """Force AFL_AUTORESUME to be set to 1."""
    if "AFL_AUTORESUME" not in os.environ:
        print("AFL_AUTORESUME needs to be set to 1, setting it now")
        os.environ["AFL_AUTORESUME"] = "1"


class AbstractFuzzer:
    """Abstract class for a fuzzer."""
    name: str
    run_cnt: int
    corpus_dir: str
    output_dir: str
    command: List[str]
    dicts: List[str]
    target_binary: str
    log_path: str
    time_run_start: int

    def run(self):
        raise NotImplementedError()

    def build_command(self):
        raise NotImplementedError()

    def get_tmout(self):
        raise NotImplementedError()

    def log(self):
        raise NotImplementedError()


class AFLFuzzer(AbstractFuzzer):
    """Base class for an AFL fuzzer."""
    plot_data_dir: str

    def __init__(self, name: str, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str):
        self.name = name
        self.run_cnt = 0
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.dicts = dicts
        self.target_binary = target_binary
        self.log_path = os.path.join(self.output_dir, "ensemble_log");
        self.command = None

    def add_common_args(self):
        self.command += ['-J', str(self.get_tmout())]
        self.command += COMMON_ARGS
        for dict in self.dicts:
            self.command += ['-x', dict]
        self.command += ['-i', self.corpus_dir, '-o', self.output_dir, '--', self.target_binary, INT_MAX]

    def do_run(self):
        run_command(self.command)

    def do_run_timed(self):
        self.time_start = get_cur_time_ms()
        self.do_run()
        self.time_end = get_cur_time_ms()

    def kill_dangling_processes(self):
        kill_dangling_processes(self.target_binary)

    def run(self):
        self.build_command()
        self.do_run_timed()
        self.log()
        if FUZZBENCH_RUN:
            self.kill_dangling_processes()
        self.run_cnt += 1

    def init_log(self):
        with open(self.log_path, "w") as f:
            f.write("time_start, time_end, fuzzer, run_cnt, command\n")

    def log(self):
        if not os.path.exists(self.log_path):
            self.init_log()
        with open(self.log_path, "a") as f:
            f.write(f"{self.time_start}, {self.time_end}, {self.name}, {self.run_cnt}, {' '.join(self.command)}\n")

    def get_tmout(self):
        if TMOUT_STRAT == "const":
            return TMOUT_STRAT_CONST
        elif TMOUT_STRAT == "geom":
            return tmout_strat_geom(self.run_cnt)
        else:
            raise ValueError(f"Unknown timeout strategy: {TMOUT_STRAT}")


class CmplogFuzzer(AFLFuzzer):
    """Class for a cmplog fuzzer."""
    cmplog_target_binary: str

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str):
        self.cmplog_target_binary = cmplog_target_binary
        super().__init__("cmplog", corpus_dir, output_dir, dicts, target_binary)

    def build_command(self):
        self.command = [CMPLOG_FUZZ_BIN_NAME, '-c', self.cmplog_target_binary]
        self.add_common_args()


class FoxFuzzer(AFLFuzzer):

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str):
        super().__init__("fox", corpus_dir, output_dir, dicts, target_binary)

    def build_command(self):
        self.command = [FOX_FUZZ_BIN_NAME, '-k', '-p', 'wd_scheduler']
        self.add_common_args()

class EnsembleFuzzer:

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str, fox_target_binary: str):
        self.cmplog_fuzzer = CmplogFuzzer(corpus_dir, output_dir, dicts, target_binary, cmplog_target_binary)
        self.fox_fuzzer = FoxFuzzer(corpus_dir, output_dir, dicts, fox_target_binary)
        self.current_fuzzer = self.fox_fuzzer

    def switch_current_fuzzer(self):
        self.current_fuzzer = self.cmplog_fuzzer if self.current_fuzzer is self.fox_fuzzer else self.fox_fuzzer

    def flush_output_dir(self):
        rmtree_if_exists(self.current_fuzzer.output_dir)

    def run(self):
        force_afl_autoresume()
        self.flush_output_dir()
        while True:
            self.current_fuzzer.run()
            self.switch_current_fuzzer()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--corpus_dir", type=str, required=True, help="Directory containing the corpus")
    parser.add_argument("-o", "--output_dir", type=str, required=True, help="Directory to store output")
    parser.add_argument("-b", "--target_binary", type=str, required=True, help="Path to the target binary")
    parser.add_argument("-x", "--dicts", type=list, default=None, help="Path to the dictionaries, if not provided, will be set to all .dict files in the current directory")
    parser.add_argument("--fox_target_binary", type=str, default=None, help="Path to the target binary for fox, if not provided, will be set to [target_binary]_fox")
    parser.add_argument("--cmplog_target_binary", type=str, default=None, help="Path to the target binary for cmplog, if not provided, will be set to [target_binary]_cmplog")
    args = parser.parse_args()

    if args.cmplog_target_binary is None:
        args.cmplog_target_binary = f"{args.target_binary}_cmplog"
    if args.fox_target_binary is None:
        args.fox_target_binary = f"{args.target_binary}_fox"
    if args.dicts is None:
        args.dicts = glob.glob("*.dict")

    return args


def main(args):
    fuzzer = EnsembleFuzzer(args.corpus_dir, args.output_dir, args.dicts, args.target_binary, args.cmplog_target_binary, args.fox_target_binary)
    try:
        fuzzer.run()
    except KeyboardInterrupt:
        print("Ending ensemble run")


if __name__ == "__main__":
    main(parse_args())
