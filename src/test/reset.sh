#!/bin/bash

# generate keys
for i in 1 2 3 4
do
	cd client$i
	rm sampleSeq$i.binary 
	rm keys/KSKBSK.binary
	rm keys/Public.binary
	rm keys/Secret.binary
	cd ..
	echo -e '\n'
done

rm sampleResult.binary
