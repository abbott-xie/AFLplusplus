"""
Description: Ensemble runner for Cmplog, FOX, and ZTaint fuzzer modes.

Usage:
    python3 ensemble_runner.py -i [corpus_dir] -o [output_dir] -b [target_binary] -x [dicts]
        --fox_target_binary [fox_target_binary]
        --cmplog_target_binary [cmplog_target_binary]
        --ztaint_target_binary [ztaint_target_binary]

Note:
    - Input and output directories are managed per fuzzer instance.
    - Before each fuzzer runs, a new output directory is created.
    - The input for each subsequent fuzzer is the 'queue' directory from the previous fuzzer's output.
    - The 'queue' directory is searched within the fuzzer's output directory.
    - The environment variable 'AFL_AUTORESUME' is not set.

Alternatively, you can directly import the EnsembleFuzzer class and use it as follows:
    EnsembleFuzzer(corpus_dir, output_dir, dicts,
                   target_binary,
                   cmplog_target_binary,
                   fox_target_binary,
                   ztaint_target_binary).run()

Required fuzzer binaries in the current directory (names/paths modifiable in the script, see CMPLOG_FUZZ_BIN_NAME, FOX_FUZZ_BIN_NAME, and ZTAINT_FUZZ_BIN_NAME):
    - fox_4.30c_hybrid_start
    - cmplog_4.30c_hybrid_start
    - ztaint_4.30c_hybrid_start

Environment variables touched:
    - None
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import time

from collections import deque
from typing import List, Deque

# Fuzzer-command specific constants
INT_MAX = '2147483647'
COMMON_ARGS = ['-m', 'none', '-d', '-t', '1000+']
CMPLOG_FUZZ_BIN_NAME = "./cmplog_4.30c_hybrid_start"
FOX_FUZZ_BIN_NAME = "./fox_4.30c_hybrid_start"
ZTAINT_FUZZ_BIN_NAME = "./ztaint_4.30c_hybrid_start"

# Timeout strategies (in seconds)
TMOUT_CMPLOG = 90 * 60    # 90 minutes
TMOUT_FOX = 120 * 60      # 120 minutes
TMOUT_ZTAINT = 120 * 60   # 120 minutes


def time_s():
    """Get the current time in seconds."""
    return int(time.time())


def run_command(command: List[str]):
    """Run a checked command."""
    subprocess.run(command, check=True)


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
    time_start: int
    time_end: int

    def __init__(
        self,
        name: str,
        corpus_dir: str,
        output_dir: str,
        dicts: List[str],
        target_binary: str,
        args: List[str]
    ):
        self.name = name
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.dicts = dicts
        self.target_binary = target_binary
        self.args = args
        self.run_cnt = 0
        self.command = None
        self.timeout = False
        self.run_err = None

    def add_common_args(self):
        """Add the common arguments to the command."""
        self.command += COMMON_ARGS
        for dict_path in self.dicts:
            self.command += ['-x', dict_path]
        self.command += [
            '-i', self.corpus_dir,
            '-o', self.output_dir,
            '--',
            self.target_binary
        ] + self.args + [INT_MAX]

    def do_run(self):
        """
        Run the fuzzer with the specified command.
        If self.timeout is True, enforce timeout using subprocess.
        Handle exceptions appropriately.
        """
        try:
            if self.timeout:
                subprocess.run(self.command, check=True, timeout=self.get_timeout())
            else:
                subprocess.run(self.command, check=True)
            self.run_err = None
        except subprocess.TimeoutExpired:
            logging.info(f"Fuzzer {self.name} timed out after {self.get_timeout()} seconds")
            # Timeout is not considered an error; fuzzer can be re-queued
            self.run_err = None
        except subprocess.CalledProcessError as e:
            logging.error(f"Unexpected error while running the fuzzer")
            logging.exception(e)
            self.run_err = e

    def do_run_timed(self):
        """Run the fuzzer, timing the execution, and save any error if it fails."""
        self.time_start = time_s()
        self.do_run()
        self.time_end = time_s()

    def run(self):
        """Build the command, run the fuzzer, and log the result."""
        self.build_command()
        self.do_run_timed()
        logging.info(self.run_info())
        self.run_cnt += 1

    def run_info(self):
        """Get the run info as a JSON string."""
        return json.dumps({
            'name': self.name,
            'run_cnt': self.run_cnt,
            'time_start': self.time_start,
            'time_end': self.time_end,
            'command': self.command,
            'run_err': str(self.run_err)
        })


class CmplogFuzzer(AFLFuzzer):
    """Fuzzer class for the Cmplog mode."""
    cmplog_target_binary: str

    def __init__(
        self,
        corpus_dir: str,
        output_dir: str,
        dicts: List[str],
        target_binary: str,
        cmplog_target_binary: str,
        args: List[str]
    ):
        self.cmplog_target_binary = cmplog_target_binary
        super().__init__("cmplog", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        """
        Build the command for running the Cmplog fuzzer.
        The '-c' option specifies the cmplog-instrumented binary.
        """
        self.command = [
            CMPLOG_FUZZ_BIN_NAME,
            '-c',
            self.cmplog_target_binary
        ]
        self.add_common_args()

    def get_timeout(self):
        """Get the timeout value for the Cmplog fuzzer (in seconds)."""
        return TMOUT_CMPLOG


class FoxFuzzer(AFLFuzzer):
    """Fuzzer class for the FOX mode."""

    def __init__(
        self,
        corpus_dir: str,
        output_dir: str,
        dicts: List[str],
        target_binary: str,
        args: List[str]
    ):
        super().__init__("fox", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        """Build the command for running the FOX fuzzer."""
        self.command = [
            FOX_FUZZ_BIN_NAME,
            '-k',
            '-p',
            'wd_scheduler'
        ]
        self.add_common_args()

    def get_timeout(self):
        """Get the timeout value for the FOX fuzzer (in seconds)."""
        return TMOUT_FOX


class ZTaintFuzzer(AFLFuzzer):
    """Fuzzer class for the ZTaint mode."""
    cmplog_target_binary: str

    def __init__(
        self,
        corpus_dir: str,
        output_dir: str,
        dicts: List[str],
        target_binary: str,
        cmplog_target_binary: str,
        args: List[str]
    ):
        """
        如果传入了 cmplog_target_binary，则在构造命令时加上 -c cmplog_target_binary。
        target_binary 为 ZTaint 编译出的可执行文件。
        """
        self.cmplog_target_binary = cmplog_target_binary
        super().__init__("ztaint", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        """Build the command for running the ZTaint fuzzer."""
        if self.cmplog_target_binary:
            # 如果有 cmplog_target_binary，则像 cmplog 一样加上 -c 参数
            self.command = [
                ZTAINT_FUZZ_BIN_NAME,
                '-c',
                self.cmplog_target_binary
            ]
        else:
            # 否则普通运行
            self.command = [ZTAINT_FUZZ_BIN_NAME]
        self.add_common_args()

    def get_timeout(self):
        """Get the timeout value for the ZTaint fuzzer (in seconds)."""
        return TMOUT_ZTAINT


class EnsembleFuzzer:
    """
    EnsembleFuzzer orchestrates multiple fuzzers, running them in a coordinated manner.
    Before each fuzzer runs, a new output directory is created, and the input directory is set up by copying
    the previous fuzzer's queue into it.
    The 'queue' directory is searched within the previous fuzzer's output directory.
    The environment variable 'AFL_AUTORESUME' is not set, so each fuzzer starts fresh with the provided inputs.
    """
    output_dir: str
    fuzzer_queue: Deque[AFLFuzzer]
    initial_corpus_dir: str
    args: List[str]
    dicts: List[str]

    def __init__(
        self,
        corpus_dir: str,
        output_dir: str,
        dicts: List[str],
        target_binary: str,
        cmplog_target_binary: str,
        fox_target_binary: str,
        ztaint_target_binary: str,
        args: List[str]
    ):
        self.output_dir = os.path.join(output_dir, "ensemble_fuzzer")
        self.initial_corpus_dir = corpus_dir  # Store initial corpus directory
        self.dicts = dicts  # Store dictionaries
        self.args = args    # Store target binary arguments
        self.fuzzer_queue = deque()

        # 1. 如果没有提供这几个参数，就不会将其添加到队列
        #   - 注意这里默认 target_binary 是普通的 AFL 编译产物，必需的
        #   - cmplog_target_binary、fox_target_binary、ztaint_target_binary 则是可选的
        if ztaint_target_binary:
            self.fuzzer_queue.append(
                ZTaintFuzzer(
                    corpus_dir=None,
                    output_dir=None,
                    dicts=self.dicts,
                    target_binary=ztaint_target_binary,
                    cmplog_target_binary=cmplog_target_binary,
                    args=self.args
                )
            )
        if fox_target_binary:
            self.fuzzer_queue.append(
                FoxFuzzer(
                    corpus_dir=None,
                    output_dir=None,
                    dicts=self.dicts,
                    target_binary=fox_target_binary,
                    args=self.args
                )
            )
        if cmplog_target_binary:
            self.fuzzer_queue.append(
                CmplogFuzzer(
                    corpus_dir=None,
                    output_dir=None,
                    dicts=self.dicts,
                    target_binary=target_binary,
                    cmplog_target_binary=cmplog_target_binary,
                    args=self.args
                )
            )

    def find_queue_directory(self, output_dir):
        """
        Search the output directory recursively for a 'queue' directory.
        Return the path to the 'queue' directory if found, else None.
        """
        for root, dirs, files in os.walk(output_dir):
            if 'queue' in dirs:
                return os.path.join(root, 'queue')
        return None

    def copy_queue_to_input(self, queue_dir, input_dir):
        """
        Copy the contents of the queue directory to the new input directory.
        """
        if not os.path.exists(queue_dir):
            logging.warning(f"Queue directory {queue_dir} does not exist.")
            return
        for filename in os.listdir(queue_dir):
            src_path = os.path.join(queue_dir, filename)
            dst_path = os.path.join(input_dir, filename)
            if os.path.isfile(src_path):
                shutil.copy2(src_path, dst_path)

    def run(self):
        """
        Run the ensemble of fuzzers.
        Each fuzzer runs in a round-robin fashion.
        For each fuzzer, create a new output directory and set up the input directory appropriately.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        prev_output_dir = None  # Keep track of previous fuzzer's output directory

        while len(self.fuzzer_queue):
            fuzzer = self.fuzzer_queue.popleft()

            # Create unique input and output directories per fuzzer run
            fuzzer_output_dir = os.path.join(
                self.output_dir,
                f"{fuzzer.name}_run_{fuzzer.run_cnt}"
            )
            os.makedirs(fuzzer_output_dir, exist_ok=True)

            # Set up the input directory
            if fuzzer.run_cnt == 0:
                # First run of this fuzzer
                if prev_output_dir is None:
                    # First fuzzer overall, use initial corpus_dir
                    fuzzer_input_dir = self.initial_corpus_dir
                else:
                    # Subsequent fuzzers, use the previous fuzzer's output queue
                    queue_dir = self.find_queue_directory(prev_output_dir)
                    if queue_dir is None:
                        logging.warning(f"No queue directory found in {prev_output_dir}. Using initial corpus.")
                        fuzzer_input_dir = self.initial_corpus_dir
                    else:
                        fuzzer_input_dir = queue_dir
            else:
                # Subsequent runs of the same fuzzer, use its previous output queue
                queue_dir = self.find_queue_directory(fuzzer.output_dir)
                if queue_dir is None:
                    logging.warning(f"No queue directory found in {fuzzer.output_dir}. Using initial corpus.")
                    fuzzer_input_dir = self.initial_corpus_dir
                else:
                    fuzzer_input_dir = queue_dir

            # Prepare the input directory by copying files
            fuzzer_input_dir_prepared = os.path.join(
                self.output_dir,
                f"{fuzzer.name}_input_{fuzzer.run_cnt}"
            )
            os.makedirs(fuzzer_input_dir_prepared, exist_ok=True)
            self.copy_queue_to_input(fuzzer_input_dir, fuzzer_input_dir_prepared)

            # Update fuzzer's input and output directories
            fuzzer.corpus_dir = fuzzer_input_dir_prepared
            fuzzer.output_dir = fuzzer_output_dir

            # Decide on timeout
            # 如果队列里还有其它的 Fuzzer，就开启超时限制
            fuzzer.timeout = len(self.fuzzer_queue) > 0

            # Run the fuzzer
            fuzzer.run()

            # After running the fuzzer, update prev_output_dir
            prev_output_dir = fuzzer.output_dir

            if isinstance(fuzzer.run_err, Exception):
                # If an actual error occurred (non-timeout), do not re-queue
                logging.info(f"Fuzzer {fuzzer.name} encountered an error and will not be re-queued.")
            else:
                # Re-queue the fuzzer to run again
                self.fuzzer_queue.append(fuzzer)

        # If we exit the loop, no fuzzer is left
        logging.info("Fuzzing completed: all fuzzers have been processed.")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--corpus_dir", type=str, required=True,
                        help="Directory containing the corpus")
    parser.add_argument("-o", "--output_dir", type=str, required=True,
                        help="Directory to store output")
    parser.add_argument("-b", "--target_binary", type=str, required=True,
                        help="Path to the vanilla AFLplusplus-instrumented target binary")
    parser.add_argument("-a", "--args", type=str, nargs="*", default=[],
                        help="Arguments to pass to the target binary")
    parser.add_argument("-x", "--dicts", type=str, nargs="+", default=None,
                        help="Path to the dictionaries; if not provided, will use all .dict files in the current directory")
    parser.add_argument("--fox_target_binary", type=str, required=False,
                        help="Path to the FOX-instrumented target binary (optional)")
    parser.add_argument("--cmplog_target_binary", type=str, required=False,
                        help="Path to the cmplog-instrumented target binary (optional)")
    parser.add_argument("--ztaint_target_binary", type=str, required=False,
                        help="Path to the ZTaint-instrumented target binary (optional)")
    return parser.parse_args()


def main(args):
    """Main function to run the ensemble fuzzer."""
    os.makedirs(args.output_dir, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(args.output_dir, "ensemble_runner.log"),
        level=logging.DEBUG
    )

    if args.dicts is None:
        args.dicts = [os.path.abspath(f) for f in os.listdir('.') if f.endswith('.dict')]
        if not args.dicts:
            logging.warning("No dictionaries found; proceeding without any dictionaries.")
    else:
        args.dicts = [os.path.abspath(dict_path) for dict_path in args.dicts]

    fuzzer = EnsembleFuzzer(
        corpus_dir=args.corpus_dir,
        output_dir=args.output_dir,
        dicts=args.dicts,
        target_binary=args.target_binary,
        cmplog_target_binary=args.cmplog_target_binary,
        fox_target_binary=args.fox_target_binary,
        ztaint_target_binary=args.ztaint_target_binary,
        args=args.args
    )
    fuzzer.run()


if __name__ == "__main__":
    main(parse_args())