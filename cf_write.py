#!/usr/bin/env python3
import sys

from copyfail_primitive import copy_fail_path


path = sys.argv[1]
offset = int(sys.argv[2], 0)
data = bytes.fromhex(sys.argv[3][4:]) if sys.argv[3].startswith("hex:") else sys.argv[3].encode()
copy_fail_path(path, data, offset)
