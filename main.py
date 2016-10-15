#!/usr/bin/python
import sys
import os

import numpy as np
import argparse

from random import randint

import random
from simplecrypt import encrypt, decrypt, DecryptionException
from Crypto.Hash import SHA

import Crypto

input = "CorrectPassword"

file1 = open('history.txt', 'w+')
file2 = open('input.txt', 'r')

# standard deviation
k_val = 2
# mean
t_val = 10

q_val = Crypto.Util.number.getPrime(160, randfunc=None)
#print q_val

# fixed file size as asked
h_history_file_size = 600
history_file_name = 'history'
# number of features
h_max_entries = 5   # 5 we'll save, from 6th we'll start checking
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

def polynomial_gen(degree, h_pwd):
  coefficient = [h_pwd] + random.sample(xrange(100), degree)
  return Polynomial(coefficient)

#print coefficient    
var_new = polynomial_gen(max_feature-1, h_pwd)
print var_new 
#print random.randint(0, 10000)

h_pwd = random.randrange(0, q_val-1)
polynomial = polynomial_gen(max_feature-1, h_pwd)
print polynomial.val(1)



'''def alpha_cal(input ,polynomial):
	g_ = hmac.new(input, msg=2*i, digestmod=None) 
	var_ =  (polynomial.val(g_) + g_) % q_val
	return var_
'''

def SHAtoLONG(pwd, input_i):
  shaed = SHA.new(str(input_i) + pwd).hexdigest()
  val_ = long(''.join([str(ord(h)) for h in shaed])) # converts into long -- ascii conversion
  return val_



def alpha_cal(pwd, i, polynomial):
	return polynomial.val(2*i) + (SHAtoLONG(pwd, 2*i) % q_val)


def beta_cal(pwd, i, polynomial):
	return polynomial.val(2*i+1) + (SHAtoLONG(pwd, 2*i+1) % q_val)	

'''
hashed = SHA.new(str('ravi')).hexdigest()
nums = long(''.join([str(ord(c)) for c in hashed]))
print hashed
print "rpg" 
#print long(str(ord(c)) for c in hashed)
print nums
'''





'''
def beta_cal(input ,polynomial):
	#hashlib.sha224(input.hexdigest()
	g_ = hmac.new(input, msg=2*i+1, digestmod=None) 
	var_ =  (polynomial.val(g_) + g_) % q_val
	return var_
'''

def parser(test_file):
	m_features = []
	for i in xrange(0, len(test_file), 2):  # first two lines at a time
	    pwd = test_file[i]
	    features = map(int, test_file[i+1].split(','))
	    print features
	    # we also need to validate the inputs sometime later....
	    if i < (h_max_entries * 2) - 2:
	      m_features.append(features)
	      print "Done step 1"
	    elif i == (h_max_entries * 2) - 2:
	      m_features.append(features)
	      h_pwd , table_instruct = create_instruct_table(m_features, pwd)
	      create_hist(m_features, hpwd)
	      print "Done step 2"
	    else:
	      # sends entries to try_login
	      m_features = try_login(pwd, features, table_instruct)
	      if (m_features == 0):
	        continue
	      table_instruct, hpwd = create_instruct_table(m_features, pwd)
	      create_hist(m_features, hpwd)







def create_instruct_table(history_features, password):
  # this provides the basic calculations needed for the funtions in the paper
  stds = np.std(history_features, axis = 0)
  means = np.mean(history_features, axis = 0)
  hpwd = random.randrange(0, LARGE_PRIME-1)
  polynom = getRandomPolynomial(MAX_FEATURES-1, hpwd)

  table_instruct=[]

  # feature is distinguishing
  for i in xrange(0, MAX_FEATURES):
    """from the definition:
       mean feature of user - k(standard deviation of user's features) < or > ti (average feature)
       average feature is provided as PARAM_T
       number of standard deviations away is provided as PARAM_K
    """
    if ((i < len(means)) and ((abs(means[i] - PARAM_T) - 0.0001) > (PARAM_K * stds[i]))):
      if (means[i] < PARAM_T):
        # feature is slow so a true value in alpha and random in beta
        table_instruct.append([
          getAlpha(password, i+1, polynom),
          getBeta(password+str(random.randrange(0, 1000)), i+1, getRandomPolynomial(MAX_FEATURES-5, random.randrange(0, LARGE_PRIME-1)))
        ])
      else:
        # feature is fast so set a random number in the alpha column and true in beta
        table_instruct.append([
          getAlpha(password+str(random.randrange(0, 1000)), i+1, getRandomPolynomial(MAX_FEATURES-5, random.randrange(0, LARGE_PRIME-1))),
          getBeta(password, i+1, polynom)
        ])
    # not distinguishing so both alpha and beta have true values (right hpwd, polynom, password)
    else:
      table_instruct.append([
        getAlpha(password, i+1, polynom),
        getBeta(password, i+1, polynom)
      ])
  return [h_pwd, table_instruct]






'''
content = file2.readlines()

print len(content)

if __name__ == '__main__':
	with open(sys.argv[1], 'r') as my_file:
		parser(my_file.readlines())

'''
























          