#!/usr/bin/python
import sys
import os

import numpy as np
import argparse

import random
from simplecrypt import encrypt, decrypt, DecryptionException

import Crypto


# standard deviations: par_k
std_val = 2
# mean: Par_t
mean_val = 10

q_val = Crypto.Util.number.getPrime(160, randfunc=None)

# fixed file size as asked
h_history_file_size = 500
history_file_name = 'hpd'
# number of features
h_max_entries = 8