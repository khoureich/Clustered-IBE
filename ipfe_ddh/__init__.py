'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         12/2023
|
'''

from charm.toolbox.pairinggroup import ZR, G1
import time

class IPFEDDH():
    def __init__(self, group_obj, l):
        self.name = 'ipfe-ddh'
        self.group = group_obj
        self.l = l
        
    def setup(self):
        g1 = self.group.random(G1)
        g2 = self.group.random(G1)
        
        s = []
        for i in range(self.l):
            s.append(self.group.random(ZR))
            
        t = []
        for i in range(self.l):
            t.append(self.group.random(ZR))
                
        h = []
        for i in range(self.l):
            h.append((g1**s[i])*(g2**t[i]))
                        
        msk = {'s':s, 't':t}
        mpk = {'g1':g1, 'g2':g2, 'h':h}
        
        return msk, mpk
    
    def keygen(self, msk, x):
        s = msk['s']
        t = msk['t']
        
        a = self.inner_prod(s, x)
        b = self.inner_prod(t, x)
        
        SKx = {'x':x, 'a':a, 'b':b}
        return SKx
    
    def encrypt(self, mpk, y):        
        r = self.group.random(ZR)
        g1 = mpk['g1']
        g2 = mpk['g2']
        h = mpk['h']
        
        C = g1**r
        D = g2**r
        
        E = []
        for i in range(self.l):
            E.append((g1**y[i])*(h[i]**r))
        
        Cy = {'C':C, 'D':D, 'E':E}
        return Cy
    
    def decrypt(self, SKx, Cy):
        x = SKx['x']
        a = SKx['a']
        b = SKx['b']
        C = Cy['C']
        D = Cy['D']
        E = Cy['E']
        
        num = 1
        for i in range(self.l):
            num *= (E[i]**x[i])
        
        den = (C**a)*(D**b)
        Ex = num/den
        
        return Ex # not log(Ex)
        
    def inner_prod(self, x, y):
        ip = 0
        for i in range(len(x)):
            ip += x[i]*y[i]
        return ip