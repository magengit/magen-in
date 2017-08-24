#! /usr/bin/python3

import os
import sys

current_path = os.path.dirname(os.path.realpath(__file__))
one_level_up = os.path.dirname(current_path)
sys.path.append(os.path.dirname(current_path))
sys.path.append(os.path.dirname(one_level_up))
