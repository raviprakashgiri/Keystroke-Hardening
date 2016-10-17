#!/usr/bin/python
import sys
import os
import numpy as np

from random import randint
import random
from simplecrypt import encrypt, decrypt, DecryptionException
from Crypto.Hash import SHA
import os.path
import time,sys
from Crypto.Cipher import AES
import base64
import Crypto

#encryption mode
mode_encrypt= 'encrypt'
 
# standard deviation
k_val = 2
# mean
t_val = 10

q_val = Crypto.Util.number.getPrime(160, randfunc=None)
#print q_val

# fixed file size as asked
history_file_name = "history"
history_file_size = 500
contents = ''
# number of features
h_max_entries = 5   # 5 we'll save, from 6th we'll start checking
h_pwd = randint(0, q_val -1)
#print h_pwd
pwd_len = 16
max_features = pwd_len - 1
feature_type = {}
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
var_new = polynomial_gen(max_features-1, h_pwd)
#print var_new 
#print random.randint(0, 10000)

h_pwd = random.randrange(0, q_val-1)
polynomial = polynomial_gen(max_features-1, h_pwd)
#print polynomial.val(1)


def SHAtoLONG(pwd, input_i):
  shaed = SHA.new(str(input_i) + pwd).hexdigest()
  val_ = long(''.join([str(ord(h)) for h in shaed])) # converts into long -- ascii conversion
  return val_

# we need to hash h_pwd into string to use it as a input for AES
def SHAtoSTRING(input_):
  return SHA.new(str(input_)).hexdigest()

def alpha_cal(pwd, i, polynomial):
	return polynomial.val(2*i) + (SHAtoLONG(pwd, 2*i) % q_val)


def beta_cal(pwd, i, polynomial):
	return polynomial.val(2*i+1) + (SHAtoLONG(pwd, 2*i+1) % q_val)	


def validateInputs(pwd, features):
  if (len(pwd) > pwd_len):
    print 'The maximum password length is '+ str(pwd_len) + ' characters'
    sys.exit()
  if (len(pwd)-2 != len(features)):
    print 'The length of password must equal number of feature values'
    sys.exit()

#========== input file parser begins: ===========#

def parser(test_file):
  m_features = []
  for n in xrange(0, len(test_file), 2):  # first two lines at a time
      pwd = test_file[n]
      features = map(int, test_file[n+1].split(','))
      #print features
      # we also need to validate the inputs sometime later....
      validateInputs(pwd, features)
      if n < (h_max_entries * 2) - 2:
        m_features.append(features)
        print 's'
        #print m_features
      elif n == (h_max_entries * 2) - 2:
        m_features.append(features)
        h_pwd, table_instruct,feature_type = create_instruct_table(m_features, pwd)
        CreateHistory(m_features, h_pwd)
        print 's'
      else:
        print 'n:',n
        print features
        m_features = ready_for_login(pwd, features, table_instruct,feature_type)
        print m_features
        if (m_features == 0):
          continue
        h_pwd, table_instruct,feature_type = create_instruct_table(m_features, pwd)
        print feature_type
        #CreateHistory(h_pwd, contents =m_features) 
        CreateHistory(m_features, h_pwd)



#========== input file parser ends: ===========#


#========== ready_for_login begins: ===========#
def ready_for_login(pwd, features, table_instruct,feature_type):
# return feature from the history file adding new feature on success
  try:
    print 'feature_type' ,feature_type
    h_pwd = getHpwdFromTableInstruct(table_instruct, features, pwd)
    #print 'feature_type' ,feature_type
    text_ = DecryptFromFile(
      SHAtoSTRING(h_pwd))
    print text_
  # if fails then we print 0 to denote denied entry
  except DecryptionException:
    print 'decrypt fail'
    for key in feature_type:
          if (feature_type[key] =='slow'):
              print 'was slow made fast'
              feature_type[key] = 'fast'
          else:
              feature_type[key] = 'slow'
          print 'retrying with feature changed:', key    
          h_pwd = getHpwdFromTableInstruct_ec(table_instruct, feature_type, pwd)
          try:
                text_ = DecryptFromFile(SHAtoSTRING(h_pwd))
          except DecryptionException:
                print 'didnt work'
                continue
                
  
    print 'f'
    return 0
    
                   
      
  # finally the user has been granted access to the system
  print 's'
  
  m_features = []
	# appends the new feature in the history file
  for line in text_.splitlines(): 
    m_features.append(map(int, line.split(',')))
  m_features.append(features)
  return m_features
#========== ready_for_login ends: ===========#


#=============== HISTORY FILE CREATION BEGINS ==================#
#IF WE'LL USE THIS ONE,WE WON'T NEED THE NEXT 

# encrypt msg by key with AES, saves into binary file
def EncryptForFile(key, text_):
  pad_msg = "$$$$" + text_ # Separator between the text_ and the padder
  print pad_msg
  encrypted_text = encrypt(key, pad_msg.rjust(history_file_size, 'S'))# extra will be padded by 'S' char
  with open(history_file_name, 'wb') as f:
    f.write(encrypted_text)

# decrypts msg by key, 
def DecryptFromFile(key):
  with open(history_file_name, 'rb') as f:
    cipher_text = f.read()
  pad, plain_text = decrypt(key, cipher_text).split("$$$$")
  return plain_text

# creates and updates the history file 
def CreateHistory(m_features, h_pwd):
  str_ = ''
  for i in xrange(1, len(m_features)):
    str_ += ','.join([str(j) for j in m_features[i]]) + '\n'
  print str_
  EncryptForFile(SHAtoSTRING(h_pwd),str_)

#=============== HISTORY FILE CREATION ENDS ==================#

#========== Create history file begins: ===========#
def do_encryptdecrypt(h_pwd,contents, mode_encrypt):
        start_time = time.time()
        
        if mode_encrypt == 'encrypt':
          enc_secret = AES.new(str(h_pwd)[:32])
          tag_string = (str(contents) +
                  (AES.block_size -
                   len(str(contents)) % AES.block_size) * "\0")
          text = base64.b64encode(enc_secret.encrypt(tag_string))
        elif mode_encrypt == 'decrypt':
          dec_secret = AES.new(str(h_pwd)[:32])
          raw_decrypted = dec_secret.decrypt(base64.b64decode(cipher_text))
          text = raw_decrypted.rstrip("\0")
        total_time = round(time.time() - start_time, 2 )
        print('%sion time: %s seconds' %(mode_encrypt, str(total_time)))
        return text
        

def check_decrypt(h_pwd):
        if (os.path.isfile('./history.txt')):
          f1 = open('history.txt')
        contents = do_encryptdecrypt(h_pwd,f1.read(),mode_encrypt='decrypt')
        if contents is not None:
          return true
        
def create_hist(h_pwd, contents):
        if contents is None:
           check_decrypt(h_pwd)
        f2 = open('history.txt','wb')
        res = do_encryptdecrypt(h_pwd,contents,mode_encrypt='encrypt')
        f2.seek(history_file_size - len(res))
        f2.write(res)
        f2.close()
        print ('Done hist file creation')

#========== create history file ends: ===========#




#========== instruction table creation begins: ===========#

def create_instruct_table(m_features, pwd):
  print max_features
  sigma = np.std(m_features, axis = 0)
  average = np.mean(m_features, axis = 0)
  h_pwd = random.randrange(0, q_val-1)
  poly = polynomial_gen(max_features-1, h_pwd)

  table_instruct=[]
  feature_type = {}
  for i in xrange(0, max_features):
    #i < h check below
    if ((i < len(average)) and ((abs(average[i] - t_val) - 0.0001) > (k_val * sigma[i]))):#0.001,small float subtraction problem
      if (average[i] < t_val):
        feature_type[i] = 'slow'
        table_instruct.append([
          alpha_cal(pwd, i+1, poly),
          beta_cal(pwd+str(random.randrange(0, 1000)), i+1, polynomial_gen(max_features-5, random.randrange(0, q_val-1)))
        ])
      else:
        feature_type[i] = 'fast'
        table_instruct.append([
          alpha_cal(pwd+str(random.randrange(0, 1000)), i+1, polynomial_gen(max_features-5, random.randrange(0, q_val-1))),
          beta_cal(pwd, i+1, poly)
        ])
    else:
      feature_type[i] = 'undis' 
      table_instruct.append([
        alpha_cal(pwd, i+1, poly),
        beta_cal(pwd, i+1, poly)
      ])
  return [h_pwd, table_instruct, feature_type]

#========== instruction table creation ends: ===========#



#============== retrieval from instruction table begins===================#

# retrieves h_pwd from instruction table based on the new feature  and pwd

def getHpwdFromTableInstruct(table_instruct, features, pwd):
  xy_values = []
  for i in xrange(1, max_features+1):
    #boundary check if i > len(features)... add as the chosen password length is 65, so (64-15) will have to fill up with no distinguishable values
    if (i > len(features)):
      xy_values.append([2*i, table_instruct[i-1][0] - ((SHAtoLONG(pwd, 2*i) % q_val))])
      continue
    # check to see if the feature is less than the provided mean
    if (features[i-1] < t_val):
        xy_values.append([2*i, table_instruct[i-1][0] - ((SHAtoLONG(pwd, 2*i) % q_val))])
    # if the provided feature is greater than the mean
    else:
      xy_values.append([2*i+1, table_instruct[i-1][1] - ((SHAtoLONG(pwd, 2*i+1) % q_val))])
  return h_pwdLagrange(xy_values, max_features)

# retrieves h_pwd from instruction table based on the new feature and pwd
# called for error correction

def getHpwdFromTableInstruct_ec(table_instruct, feature_type, pwd):
  xy_values = []
  #print 'feature_type' ,feature_type
  f = -1
  for i in xrange(1, max_features+1):
    f+= 1
   
    # check to see if the feature is less than the provided mean
    if (feature_type[f] == 'fast'):
        xy_values.append([2*i, table_instruct[i-1][0] - ((SHAtoLONG(pwd, 2*i) % q_val))])
    # if the provided feature is greater than the mean
    else:
      
      xy_values.append([2*i+1, table_instruct[i-1][1] - ((SHAtoLONG(pwd, 2*i+1) % q_val))])

  return h_pwdLagrange(xy_values, max_features)



# lagrange interpolation to get h_pwd from xy values
def h_pwdLagrange(xy_values, feature_num):
  h_pwd = 0
  nums = []
  dens = []
  dens_sum = 1
  for i in xrange(0, feature_num):
    lambda_num = 1
    lambda_den = 1
    for j in xrange(0, feature_num):
      if (i != j):
        lambda_num *= xy_values[j][0]
        lambda_den *= xy_values[j][0] - xy_values[i][0]
    nums.append(lambda_num * xy_values[i][1])
    dens.append(lambda_den)
  for i in xrange(0, len(nums)):
    h_pwd += get_Num(i, nums, dens)
    dens_sum *= dens[i]
  return h_pwd/dens_sum # floor division to avoide float conversion

#used to minimize the divisions, copied form internet, mentione the source later if necessary...
def get_Num(index, nums, dens):
  num = 1
  for i in xrange(0, len(nums)):
    if i == index:
      num *= nums[i]
    else:
      num *= dens[i]
  return num
#============== retrieval from instruction table ends===================#


'''
content = file2.readlines()

print len(content)
'''

if __name__ == '__main__':
  with open(sys.argv[1], 'r') as my_file:
    parser(my_file.readlines())      
