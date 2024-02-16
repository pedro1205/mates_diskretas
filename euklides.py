# -*- coding: utf-8 -*-
"""
Created on Fri Feb 16 12:28:36 2024

@author: pedrito.com
"""

num1 = int(input("Ingresa un numero: "))
num2 = int(input("Ingresa otro numero: "))

if num1 > num2:
    a = num1
    b = num2
    
else:
    a = num2
    b = num1


mcd = a
while (a > 0 and b > 0):
    tmp = a 
    a = b
    b = tmp % a
    
    
mcd = a
print(mcd)

