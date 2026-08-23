'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         08/2026
|
| In this implementation, the ID is a string (e.g. email, name, etc.) that is hashed to an element in ZR.
| It is no longer necessary to have a list L_alpha in a cluster.
| x_beta is a Vandermonde vector that is generated from the hashed ID.
|
| The main problem with version 1 of the CIBE implementation is that there are far
| more clusters than necessary (clusters are sparse), which is not efficient.
| The problem with version 2 is the need to specify the number of clusters and the number of IDs in advance,
| which is not practical. In addition, there exists sparse clusters.
| This version 3 eliminates the shortcomings of version 1 and 2 at the cost of a counter
| that is incremented each time a new secret key is generated and the use of ID aliases for encryption.
| A new cluster is created only when the current cluster is full (i.e. contains l-1 IDs).
| The ID alias is the original ID concatenated with a cluster number.
| The main objective is to obtain the maximum compression of many public-keys into a public parameter.
|
'''
import sys
import math

from charm.toolbox.pairinggroup import ZR
from ipfe_ddh import IPFEDDH

class CIBE3():
    # In this implementation, the ID is a string, it can be an email, a name, etc.
    # An ID alias is the original ID concatenated with a cluster number.
    # The original ID is used to generate the secret key, while the ID alias (returned by keygen) is used for encryption.
    # We hash the ID to an element in ZR.

    # l: the functionality parameter of the IPFE
    def __init__(self, group_obj, l):
        self.name = 'CIBE'
        self.ipfe = IPFEDDH(group_obj, l)
        self.l = l
        
    def setup(self):
        MSK = {}
        params = {'MPK':{}, 'c': 0}        
        # c is a counter that is incremented each time a new secret key is generated
        # It is used to determine the cluster associated with a given ID.
        return MSK, params
    
    
    def keygen(self, params, MSK, ID):
        ID_ZR = self.ipfe.group.hash(ID, ZR)
        c = params['c']
        alpha = str(math.floor(c/(self.l-1)))
        
        if alpha not in MSK:
            (msk_alpha, mpk_alpha) = self.ipfe.setup()
            MSK[alpha] = msk_alpha
            params['MPK'][alpha] = mpk_alpha
        
        # We use Vandermonde vectors e.g. x_beta = [1, a, a^2, a^3, ... a^(l-1)] where a = hash_to_ZR(ID).
        # It is no longer necessary to store these vectors in L[alpha].
        # Each cluster contains at most l-1 Vandermonde vectors in (ZR*)^l created from different Ids,
        # therefore, these vectors are linearly independent.

        x_beta = self.vandermonde_vector(ID_ZR, self.l)            
        SKx_beta = self.ipfe.keygen(MSK[alpha], x_beta)
        SKx_beta['x'] = x_beta[1]
        params['c'] = c + 1

        ID_alias = f'{ID}${c}'
                    
        return SKx_beta, ID_alias
        
    
    def encrypt(self, params, ID_alias, m):
        id_no = ID_alias.split('$')
        id = id_no[0]
        no = int(id_no[1])
        ID_ZR = self.ipfe.group.hash(id, ZR)
        alpha = str(math.floor(no/(self.l-1)))

        if alpha not in params['MPK']:
            print (f'Encryption error. First generate a secret key for identity {id}. Encryption is aborted!')
            sys.exit(1)

        x_beta = self.vandermonde_vector(ID_ZR, self.l)
        
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