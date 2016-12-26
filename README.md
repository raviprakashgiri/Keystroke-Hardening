Password Hardening With Keystroke Dynamics
==========================================

**Keystroke Hardening** is the light-weight implementation of an authentication system which is based on the hard password as well as the keystroke dynamics captured while typing the password.


**Recommended read:** [Fabian et al.](http://cs.unc.edu/~fabian/papers/acm.ccs6.pdf)

Contents
--------

* [Usage](#usage)<br />
  How to run the project with given input files.

* [Examples](#examples)<br />
  A few examples to get you started.

* [Module Structure](#module-structure)<br />
  A brief introduction to the structure of the exported module.


Usage
---------------

### Python

```
$> apt-get install python2.7
```

### Crypto Library

Security:

```sh
$> pip install simple-crypt
```
Authenticity:

```sh
$> pip install pycrypto
```


**NOTE:** Remember to replace the version with the one [report](https://github.com/raviprakashgiri/KeystrokeHardening/blob/master/SecAuth_report.pdf) mentioned in project.

Examples
--------

### Running without error corrction

```sh
$> python main.py input1.txt
```
### Running with error corrction


```sh
$> python main.py -e input5.txt
```

Module Structure
-----------------
### parser()

This function takes the input text files (containing the keystrokes of the user, along with the password) and validates the inputs. Once the validation is done a look-up in the instruction table is done followed by in history file.

### ready_for_login()

Once the parser is done, the control is passed to ready_for_login(). It contains the error-correction part also along with the normal program flow. Encrypted history file is decrypted by a call from this function and the new features are added into it.

### create_instruct_table()

Used to calculate the alpha beta login values. First the average and standard deviation value of the login features area calculated, then the corresponding values of alpha and beta are appended into the instruction table.

### h_pwdLagrange()

The function is used to calculate the hardened password and x y values using Lagrange Interpolation.


Output
-----------------
The output will be in binary (0/1) - 1 indicating successful login, 0 indicating failed login attempt corresponding to the input features.
