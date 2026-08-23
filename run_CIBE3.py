'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         08/2026
|
'''
import random
import string

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.toolbox.pairinggroup import G1
from cibe3 import CIBE3

def main():
    pairing_group = PairingGroup('MNT224')
    
    # the cluster size or the functionality parameter of the IPFE 
    l = 22

    # create an instance
    cibe3 = CIBE3(pairing_group, l)
    
    # setup
    (MSK, params) = cibe3.setup()
    
    # generate a key
    ID = "xyz"
    sk, ID_alias = cibe3.keygen(params, MSK, ID)
    print(f'ID alias for ID {ID}: {ID_alias}')
    # print(f'secret key: {sk}\n')
    
    # encrypt a message
    m = cibe3.ipfe.group.random(G1)
    C = cibe3.encrypt(params, ID_alias, m)
    # print(f'cipher_text: {C}\n')
    
    # decryption
    rec_m = cibe3.decrypt(params, sk, C)
    
    # correctness
    if rec_m == m:
        print('Successful decryption.')
    else:
        print('Decryption failed.')
    
        
    
if __name__ == "__main__":
    main()