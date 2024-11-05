'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         10/2024
|
'''
import sys
import math

from charm.toolbox.pairinggroup import ZR
from ipfe_ddh import IPFEDDH

class CIBE():
    def __init__(self, group_obj, l):
        self.name = 'CIBE'
        self.ipfe = IPFEDDH(group_obj, l)
        self.l = l
        
    def setup(self):
        MSK = {}
        params = {'MPK':{}, 'L':{}}
        
        return MSK, params
    
    
    def keygen(self, params, MSK, ID):
        alpha = int(math.floor(ID/(self.l-1)))
        beta = ID % (self.l-1)
        L = params['L']
        
        print(f'Active cluster: {alpha}, vector number: {beta}')  
        
        if alpha not in MSK:
            (msk_alpha, mpk_alpha) = self.ipfe.setup()
            MSK[alpha] = msk_alpha
            params['MPK'][alpha] = mpk_alpha
        
        # We use Vandermonde vectors e.g. [1, a, a^2, a^3, ... a^(l-1)], therefore we only save the integer a in L_alpha and in SKx_beta
        if alpha not in L:
            L[alpha] = {}
            
        if beta in L[alpha]:
            x_beta = self.vandermonde_vector(L[alpha][beta], self.l)
        else:
            x_beta = self.get_valid_vandermonde_vector(L[alpha], self.l)
            L[alpha][beta] = x_beta[1]
            
        SKx_beta = self.ipfe.keygen(MSK[alpha], x_beta)
        SKx_beta['x'] = x_beta[1]
                    
        return SKx_beta
        
    
    def encrypt(self, params, ID, m):
        alpha = int(math.floor(ID/(self.l-1)))
        beta = ID % (self.l-1)
        L = params['L']
        
        try:
            x_beta =  self.vandermonde_vector(L[alpha][beta], self.l)
        except:
            print (f'Encryption error. First generate a secret key for identity {ID}. Encryption is aborted!')
            sys.exit(1) 
        
        y = []
        for i in range(self.ipfe.l):
            r_i = self.ipfe.group.random(ZR)
            y.append(x_beta[i]*r_i)  
                
        mpk_alpha = params['MPK'][alpha]
        g1 = mpk_alpha['g1']
        innerProd_xy = self.ipfe.inner_prod(x_beta,y)
        C1 = m*(g1**innerProd_xy)
        C2 = self.ipfe.encrypt(mpk_alpha,y)
              
        return {'C1':C1, 'C2':C2}
        
    
    def decrypt(self, params, SK, C):        
        # recompute the Vandermonde vector
        _x =  self.vandermonde_vector(SK['x'], self.l)
        SK['x'] = _x
        
        rho = self.ipfe.decrypt(SK, C['C2'])
        return C['C1']/rho
    
    
    # create a Vandermonde vector from an integer a.  e.g. [1, a, a^2, a^3, ... a^(l-1)] 
    def vandermonde_vector(self, a, l):
        v = []
        for i in range(self.l):
            v.append(a**i)
            
        return v
    
    # get a valid Vandermonde vector x_beta such that the set of vectors in L_alpha U x_beta is linearly independent
    def get_valid_vandermonde_vector(self, L_alpha, l):
        while True:
            a = self.ipfe.group.random(ZR) 
            found = False
            for i in L_alpha:   
                if a == L_alpha[i]:
                    found = True
                    break

            if(not found):
                x_beta = self.vandermonde_vector(a, l)
                return x_beta