#!/usr/bin/python
import sys
import os

import numpy as np
import argparse

from random import randint

import random
from simplecrypt import encrypt, decrypt, DecryptionException
from Crypto.Hash import SHA

import time,os,sys,transpositionEncrypt,transpositionDecrypt

import Crypto

input = "CorrectPassword"


#encryption mode
mode_encrypt= 'encrypt'
 
# standard deviation
k_val = 2
# mean
t_val = 10

q_val = Crypto.Util.number.getPrime(160, randfunc=None)
#print q_val

# fixed file size as asked
h_history_file_size = 600
contents = ''
# number of features
h_max_entries = 5   # 5 we'll save, from 6th we'll start checking
h_pwd = randint(0, q_val -1)
#print h_pwd
pwd_len = 25
max_feature = pwd_len - 1
translated = ''


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
		      create_hist(contents = m_features, h_pwd)
	      	print "Done step 1"
	    else:
	    	m_features = ready_for_login(pwd, features, table_instruct) # need to do it later
	    	if (m_features == 0):
	        	continue
	      	h_pwd, table_instruct = create_instruct_table(m_features, pwd)
	      	create_hist(m_features, h_pwd) 

#========== input file parser ends: ===========#



#========== ready_for_login begins: ===========#
def ready_for_login():
	pass
#========== ready_for_login ends: ===========#




#========== Create history file begins: ===========#
def do_encryptdecrypt(h_pwd,content, mode_encrypt):
        start_time = time.time()
        if mode_encrypt = 'encrypt':
          translated_ = transpositionEncrypt.ecryptMessage(h_pwd,content)
        elif mode_encrypt = 'decrypt':
          translated_ = transpositionDecrypt.decryptMessage(h_pwd,content)
        total_time = round(time.time() - start_time, 2 )
        print('%sion time:' %(mode_encrypt.title(), total_time))
        return translated_

def check_decrypt(h_pwd)
        if(os.path.exists('history.txt'):
        f1 = open('history.txt')
        contents = do_encryptdecrypt(h_pwd,f1.read(),mode_encrypt='decrypt')
        if contents is not None:
        return true
        
def create_hist(contents, h_pwd)
        f2 = open('history.txt','wb')
        res = do_encryptdecrypt(h_pwd,contents,mode_encrypt='encrypt')
        f2.seek(h_history_file_size - len(res))
        f2.write()
        f2.close()
        print ('Done hist file creation'

#========== create history file ends: ===========#




#========== instruction table creation begins: ===========#

def create_instruct_table(m_features, pwd):
  
  sigma = np.std(m_features, axis = 0)
  average = np.mean(m_features, axis = 0)
  h_pwd = random.randrange(0, q_val-1)
  poly = polynomial_gen(max_features-1, h_pwd)

  table_instruct=[]

  for i in xrange(0, max_features):
    
    if ((i < len(average)) and ((abs(average[i] - t_val) - 0.0001) > (k_val * sigma[i]))):
      if (average[i] < t_val):
        
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


























          
