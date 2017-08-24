#! /usr/bin/python3
"""
- Update path for importing <svc> modules from workspace tree to add
     magen-<svc>/<svc> and magen-<svc>
- Assumed to be in magen-<svc>/<svc>/<svc>_server/dev
  - magen-<svc> is 3 levels up
  - this file is in separate directory so can arrange not to install it
"""
import os
import sys

current_path = os.path.dirname(os.path.realpath(__file__))
one_level_up = os.path.dirname(current_path)
two_levels_up = os.path.dirname(one_level_up)
three_levels_up = os.path.dirname(two_levels_up)
# order is significant, longer path should be first so is inserted last
sys.path.insert(1, three_levels_up)
sys.path.insert(1, two_levels_up)
