# websecmodel
This is a copied repository of https://github.com/sho-rong/webmodel as instead of the corresponding author of the following paper.  
Authors: Shimamoto Hayato, Naoto Yanai, Shingo Okamura, Jason Paul Cruz, Shouei Ou, Takao Okubo  
Title: Towards Further Formal Foundation of Web Security: Expression of Temporal Logic in Alloy and Its Application to a Security Model With Cache  
Journal: IEEE Access (Volume: 7, Pages: 74941 - 74960)  
https://ieeexplore.ieee.org/document/8730354  

# How to Install
These codes work on Alloy Analyzer: https://alloytools.org/  

By installing Alloy at first, you can execute our codes.  
Recommend you to check the availability of the source code by D. Ahkawe (https://github.com/devd/websecmodel) because the codes in this repository are extension of the codes of Ahkawe.  
After checking the execution of Ahkawe's codes, replace "declarations.als" with our "declarations.als".  

# Role of Each Code
The role of each code is as follows:  
cache.als: the code for attacks such as web cache poisoning and web cache deception.  
declarations(existing).als: identical to the original code by Ahkawe.  
declarations.als: our extension for the proposed syntax.  
test_ccheader.als: refenrece implementation for cache header.  
test_verification.als: reference implementation for verification of cache header.  

Png.files are examples of output of attacks for our codes.  

