Password Hardening With Keystroke Dynamics
==========================================
[![paper-url][]][] 

**Keystroke Hardening** is the light-weight implementation of an authentication system which is based on the hard password as well as the keystroke dynamics captured while typing the password.

[paper-url]: http://cs.unc.edu/~fabian/papers/acm.ccs6.pdf

**Recommended read:** [Fabian et al.](http://cs.unc.edu/~fabian/papers/acm.ccs6.pdf)

Features
--------
* History File [for checking the previous keystrokes](#correctness)
* Instruction Table [to store alpha, beta values in map](#performance)

Contents
--------

* [Usage](#usage)<br />
  How to run the project with given input files.

* [Examples](#examples)<br />
  A few examples to get you started.

* [Module Structure](#module-structure)<br />
  A brief introduction to the structure of the exported module.

* [Documentation](#documentation)<br />
  A list of available documentation resources.

* [Command line](#command-line)<br />
  How to use the command line utility.


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
$> python main.py testcase1.txt
```
### Running with error corrction


```sh
$> python main.py -e testcase1.txt
```

