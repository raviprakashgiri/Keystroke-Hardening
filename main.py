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
pwd_len = 12
max_feature = pwd_len - 1



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
#========== input file parser begins: ===========#

def parser(test_file):
	m_features = []
	for n in xrange(0, len(test_file), 2):  # first two lines at a time
	    pwd = test_file[n]
	    features = map(int, test_file[n+1].split(','))
	    print features
	    # we also need to validate the inputs sometime later....
	    if n <= (h_max_entries * 2) - 2:
	    	m_features.append(features)
	    	if n == (h_max_entries * 2) - 2:
		      h_pwd , table_instruct = create_instruct_table(m_features, pwd)
		      create_hist(m_features, h_pwd)
	      	print "Done step 1"
	    else:
	    	m_features = try_login(pwd, features, table_instruct)
	    	if (m_features == 0):
	        	continue
	      	table_instruct, hpwd = create_instruct_table(m_features, pwd)
	      	create_hist(m_features, hpwd)

#========== input file parser ends: ===========#




#========== instruction table creation begins: ===========#

def create_instruct_table(history_features, pwd):
  
  stds = np.std(history_features, axis = 0)
  means = np.mean(history_features, axis = 0)
  hpwd = random.randrange(0, q_val-1)
  poly = polynomial_gen(max_features-1, hpwd)

  table_instruct=[]

  
  for i in xrange(0, max_features):
    
    if ((i < len(means)) and ((abs(means[i] - PARAM_T) - 0.0001) > (PARAM_K * stds[i]))):
      if (means[i] < PARAM_T):
        
        table_instruct.append([
          alpha_cal(pwd, i+1, poly),
          beta_cal(pwd+str(random.randrange(0, 1000)), i+1, polynomial_gen(max_features-5, random.randrange(0, q_val-1)))
        ])
      else:
        
        table_instruct.append([
          alpha_cal(pwd+str(random.randrange(0, 1000)), i+1, polynomial_gen(max_features-5, random.randrange(0, q_val-1))),
          beta_cal(pwd, i+1, poly)
        ])
    
    else:
      table_instruct.append([
        alpha_cal(pwd, i+1, poly),
        beta_cal(pwd, i+1, poly)
      ])
  return [h_pwd, table_instruct]

#========== instruction table creation ends: ===========#




'''
content = file2.readlines()

print len(content)
'''

if __name__ == '__main__':
	with open(sys.argv[1], 'r') as my_file:
		parser(my_file.readlines())


























          