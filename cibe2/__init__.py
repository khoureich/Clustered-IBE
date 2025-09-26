'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         09/2025
| In this implementation, the ID is a string (e.g. email, name, etc.) that is hashed to an element in ZR.
| It is no longer necessary to have a list L_alpha in a cluster.
| x_beta is a Vandermonde vector that is generated from the hashed ID.
|
'''
import sys
import math

from charm.toolbox.pairinggroup import ZR
from ipfe_ddh import IPFEDDH

class CIBE2():
    # In this implementation, the ID is a string, it can be an email, a name, etc.
    # We hash the ID to an element in ZR.

    # If we calculate the cluster number associated with an ID with the formula
    # cluster_number = math.floor(ID/(l-1)) we risk having clusters with only one ID
    # Therefore, for optimization reasons, it is useful to specify the number of IDs (nID)
    # to manage and the number of clusters (nClusters) we want. 
    # The preceding formula becomes: cluster_number = math.floor(ID % nClusters)
    
    # nId/nClusters indicates the average number of IDs per cluster. For security reasons,
    # the number of IDs per cluster should not exceed l-1.

    # l: the functionality parameter of the IPFE
    # nID: the number of IDs
    # nClusters: the number of clusters
    def __init__(self, group_obj, l, nID, nClusters):
        self.name = 'CIBE'
        self.ipfe = IPFEDDH(group_obj, l)
        self.l = l
        self.nID = nID
        self.nClusters = nClusters
        
    def setup(self):
        MSK = {}
        params = {'MPK':{}}        
        return MSK, params
    
    
    def keygen(self, params, MSK, ID):
        # ID is a string, it can be an email, a name, etc.
        # We hash the ID to an element in ZR
        ID_ZR = self.ipfe.group.hash(ID, ZR)
        alpha = int(math.floor(int(ID_ZR) % self.nClusters))
        
        print(f'Active cluster: {alpha} for ID: {ID}.')  
        
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
                    
        return SKx_beta
        
    
    def encrypt(self, params, ID, m):
        ID_ZR = self.ipfe.group.hash(ID, ZR)
        alpha = int(math.floor(int(ID_ZR) % self.nClusters))

        if alpha not in params['MPK']:
            print (f'Encryption error. First generate a secret key for identity {ID}. Encryption is aborted!')
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
