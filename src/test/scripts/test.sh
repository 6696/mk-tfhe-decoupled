#!/bin/bash

# generate keys
for i in 1 2 3 4
do
	cd client$i
	../mk_tfhe_client-spqlios-fma g $i
	cd ..
	echo -e '\n'
done

# A
# create encrypted string for client 1
cd client1
../mk_tfhe_client-spqlios-fma e 000111
cd ..

# B
# create encrypted string for client 2
cd client2
../mk_tfhe_client-spqlios-fma e 010011
cd ..

# create encrypted string for client 3
cd client3
../mk_tfhe_client-spqlios-fma e 100100
cd ..

# create encrypted string for client 4
cd client4
../mk_tfhe_client-spqlios-fma e 111001
cd ..

echo -e '\n**************************************\n'
echo -e 'Bit cross encryption strating...\n'
echo -e '**************************************\n'

# encrypt bit sequence with other clients' keys
for i in 1 2 3 4
do
	for j in 1 2 3 4
	do
		if [[ $i -ne $j ]]; then
        		cd client$i
        		../mk_tfhe_client-spqlios-fma n ../client$j/sampleSeq$j.binary
        		cd ..
			echo -e '\n'
		fi
	done
done

#################################################

#./mk_tfhe_server-spqlios-fma c .

# decrypt bit sequence with other clients' keys
#for i in 1 2 3 4
#do
#        cd client$i
#        ../mk_tfhe_client-spqlios-fma d ../sampleResult.binary
#        cd ..
#        echo -e '\n'
#done

# finalize bit sequence and show result
#cd client1
#./mk_tfhe_client-spqlios-fma f sampleResult.binary

