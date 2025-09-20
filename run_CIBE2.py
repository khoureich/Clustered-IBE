'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         09/2025
|
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.toolbox.pairinggroup import G1
from cibe2 import CIBE2

def main():
    pairing_group = PairingGroup('MNT224')
    
    # the cluster size or the functionality parameter of the IPFE 
    l = 21
    
    # create an instance
    cibe2 = CIBE2(pairing_group, l)
    
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