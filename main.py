#!/usr/bin/python
import sys
import os

import numpy as np
import argparse

from random import randint

import random
from simplecrypt import encrypt, decrypt, DecryptionException

import Crypto


# standard deviations: par_k
std_val = 2
# mean: Par_t
mean_val = 10

q_val = Crypto.Util.number.getPrime(160, randfunc=None)
print q_val

# fixed file size as asked
h_history_file_size = 500
history_file_name = 'hpd'
# number of features
h_max_entries = 6
h_pwd = randint(0, q_val -1)
#print h_pwd
max_feature = 65



class Polynomial:
  coef = []

  def __init__(self, coef):
    self.coef = coef

  def val(self, x):
    sum_val = 0
    for i, value in enumerate(self.coef):
      sum_val = sum_val + value*pow(x, i)
    return sum_val


def getRandomPolynomial(degree, h_pwd):
  coef = [h_pwd] + random.sample(xrange(100), degree)
  return Polynomial(coef)

var_new = getRandomPolynomial(max_feature-1, h_pwd)
print var_new
