'''
| 
| Authors:      Ahmad Khoureich Ka
| Date:         10/2024
|
'''

from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR, G1
from ipfe_ddh import IPFEDDH

def main():
    pairing_group = PairingGroup('MNT224')
    
    ipfeddh = IPFEDDH(pairing_group, 5)
    
    (msk, mpk) = ipfeddh.setup()
    
    # generate a key
    x = []
    for i in range(ipfeddh.l):
        x.append(ipfeddh.group.random(ZR))
        
    SKx = ipfeddh.keygen(msk, x)
    
    # encrypt a message
    y = []
    for i in range(ipfeddh.l):
        y.append(ipfeddh.group.random(ZR))
        
    Cy =  ipfeddh.encrypt(mpk, y)   
        
    # decryption
    fy1 = ipfeddh.decrypt(SKx,Cy)
    
    # correctness
    ip = ipfeddh.inner_prod(x, y)
    fy2 = mpk['g1']**ip
    
    if fy1 == fy2:
        print('Successful decryption.')
        
    
    
if __name__ == "__main__":
    main()