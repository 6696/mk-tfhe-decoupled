#!/bin/bash

rm -rf ./server

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
../mk_tfhe_client-spqlios-fma e 000111
cd ..

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
# send intents

NET_PATH=/home/daniil/IdeaProjects/anoma5/anoma-docker-testnet/compose/
AUC_ID=$(cat $NET_PATH/auction_id | tr -d '\n')

for i in 1 2 3
do
	BID=$(base64 -w0 client$i/sampleSeq$i.binary)
	echo '[{"addr":"atest1v4ehgw36gs6rjd69xaqnj33kxqcnv3pc8qmryd6z8yeygdjrxepygwzrg4z52dekg4rrzwz9m09dm8","place_bid":{"bid": "'$BID'","bid_id": "'$i'", "auction_id": "'$AUC_ID'"  }}]' > $NET_PATH/bid$i.json

done

BID=$(base64 -w0 client4/sampleSeq4.binary)
        echo '[{"addr":"atest1v4ehgw36xfzyvs3k8yurgde5g56nvd6xgverxsf58y6nsvzxxeq5g3fsg9qngwfkx5crxd3kku48em","place_bid":{"bid": "'$BID'","bid_id": "4", "auction_id": "'$AUC_ID'"  }}]' > $NET_PATH/bid4.json


