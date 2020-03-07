# kase
This is a repository of key aggregate searchable encryption as behavior of the corresponding author of the following paper.  
Authors: Masahiro Kamimura, Naoto Yanai, Shingo Okamura, Jason Paul Cruz  
Title: Key-Aggregate Searchable Encryption, Revisited: Formal Foundations for Cloud Applications, and Their Implementation  
Journal: IEEE Access (Volume: 8 Page: 24153 - 24169)  
https://ieeexplore.ieee.org/document/8963718  

# How to Install
These codes work on mcl library: https://github.com/herumi/mcl

By installing the mcl library at first, you can execute our codes.  
Recommend you to check the availability of the source code of mcl because the codes in this repository are extension of the mcl.  
After checking the execution of the mcl, replace "sample/bls_sig.cpp" with our "bls_sig.cpp" in each directory.  
In particular, type "make sample" then the code is compiled.  The output file is "bin/bls_sig.exe".  

# Role of Each Code
The role of each code is as follows:  
firstconstruct/bls_sig.cpp: the code of the first construction in our paper.  
main/bls_sig.cpp: the code of the main construction in our paper.  

memo.txt in each directory is just a memo when we executed.   

