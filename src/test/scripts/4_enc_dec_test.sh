#!/bin/bash

# generate keys
for i in 1 2 3 4
do
	cd client$i
	../mk_tfhe_client-spqlios-fma g $i
	cd ..
	echo -e '\n'
done

# create encrypted string for client 1
cd client1
../mk_tfhe_client-spqlios-fma e 010101
cd ..

# encrypt bit sequence with other clients' keys
for i in 2 3 4
do
        cd client$i
        ../mk_tfhe_client-spqlios-fma n ../client1/sampleSeq1.binary
        cd ..
	echo -e '\n'
done

#################################################

# decrypt bit sequence with other clients' keys
for i in 1 2 3 4
do
        cd client$i
        ../mk_tfhe_client-spqlios-fma d ../client1/sampleSeq1.binary
        cd ..
	echo -e '\n'
done

# finalize bit sequence and show result
cd client1
../mk_tfhe_client-spqlios-fma f sampleSeq1.binary

