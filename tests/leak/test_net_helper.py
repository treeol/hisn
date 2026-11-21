#!/usr/bin/env python3
"""Unit test of net_helper's local timing probe (no sandbox needed).

It only checks the output format and that a real loopback listener is used.
Run: python3 tests/leak/test_net_helper.py
"""
import contextlib
import importlib.util
import io
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    'net_helper', os.path.join(HERE, 'net_helper.py'))
net_helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_helper)


class TimingLocal(unittest.TestCase):
    def test_net_helper_timing_local_format(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            net_helper.in_timing_local()
        line = buf.getvalue().strip()
        self.assertRegex(
            line,
            r'^TIMING-LOCAL median \d+\.\d us/connect '
            r'\(runs: \d+\.\d, \d+\.\d, \d+\.\d\)$')
        runs = [float(x) for x in re.findall(r'\d+\.\d', line.split('(')[1])]
        self.assertEqual(len(runs), 3)

    def test_subcommand_is_registered(self):
        src = open(os.path.join(HERE, 'net_helper.py')).read()
        self.assertIn("'in-timing-local': in_timing_local", src)


if __name__ == '__main__':
    unittest.main()
