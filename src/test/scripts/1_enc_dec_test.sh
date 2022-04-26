#!/bin/bash

i=4

# generate keys
cd client$i
../mk_tfhe_client-spqlios-fma g $i
cd ..
echo -e '\n'

# create encrypted string for client 1
cd client$i
../mk_tfhe_client-spqlios-fma e 110101
cd ..
echo -e '\n'

#################################################

# decrypt bit sequence with other clients' keys
cd client$i
../mk_tfhe_client-spqlios-fma d sampleSeq$i.binary
cd ..
echo -e '\n'

# finalize bit sequence and show result
cd client$i
../mk_tfhe_client-spqlios-fma f sampleSeq$i.binary

