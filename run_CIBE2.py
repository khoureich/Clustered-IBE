'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         09/2025
|
'''
import random
import string

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.toolbox.pairinggroup import G1
from cibe2 import CIBE2

def main():
    pairing_group = PairingGroup('MNT224')
    
    # the cluster size or the functionality parameter of the IPFE 
    l = 22

    # the number of IDs we want to manage
    nID = 10000

    # We determined the number of clusters experimentally
    # When we set nID=10000 and nClusters=1250, we get that the number
    # of vectors in a cluster varies between 1.0 and 19.0 (< l-1 = 21)
    # with a mean of 8.00 and a standard deviation of 2.83.
    nClusters = 1250

    # create an instance
    cibe2 = CIBE2(pairing_group, l, nID, nClusters)
    
    # setup
    (MSK, params) = cibe2.setup()
    
    # generate a key
    ID = "abc@g.c"
    sk = cibe2.keygen(params, MSK, ID)
    
    # encrypt a message
    m = cibe2.ipfe.group.random(G1)
    C = cibe2.encrypt(params, ID, m)
    
    # decryption
    rec_m = cibe2.decrypt(params, sk, C)
    
    # correctness
    if rec_m == m:
        print('Successful decryption.')
    else:
        print('Decryption failed.')
    
        
    
if __name__ == "__main__":
    main()
