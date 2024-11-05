'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         10/2024
|
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.toolbox.pairinggroup import G1
from cibe import CIBE

def main():
    pairing_group = PairingGroup('MNT224')
    
    # the cluster size or the functionality parameter of the IPFE 
    l = 10
    
    # create an instance
    cibe = CIBE(pairing_group, l)
    
    # setup
    (MSK, params) = cibe.setup()
    
    # generate a key
    ID = 115
    sk = cibe.keygen(params, MSK, ID)
    
    # encrypt a message
    m = cibe.ipfe.group.random(G1)
    C = cibe.encrypt(params, ID, m)
    
    # decryption
    rec_m = cibe.decrypt(params, sk, C)
    
    # correctness
    if rec_m == m:
        print('Successful decryption.')
    else:
        print('Decryption failed.')
    
        
    
if __name__ == "__main__":
    main()