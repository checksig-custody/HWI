#! /usr/bin/env python3

import ast
import os
import unittest

from hwilib.devices import __all__ as DEVICES

DEVICES_DIR = os.path.join(os.path.dirname(__file__), "..", "hwilib", "devices")


class TestEnumerateSignature(unittest.TestCase):
    def test_every_device_enumerate_takes_allow_emulators(self):
        # commands.enumerate passes four positional arguments to each device module.
        for dev in DEVICES:
            with self.subTest(device=dev):
                with open(os.path.join(DEVICES_DIR, dev + ".py")) as f:
                    tree = ast.parse(f.read())
                funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "enumerate"]
                self.assertEqual(len(funcs), 1)
                args = [a.arg for a in funcs[0].args.args]
                self.assertEqual(args, ["password", "expert", "chain", "allow_emulators"])


if __name__ == "__main__":
    unittest.main()
