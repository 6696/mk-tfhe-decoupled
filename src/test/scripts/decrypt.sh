# decrypt bit sequence with other clients' keys
rm -rf ./sampleResult.binary

cp server/sampleResult.binary ./sampleResult.binary

for i in 1 2 3 4
do
        cd client$i
        ../mk_tfhe_client-spqlios-fma d ../sampleResult.binary
        cd ..
        echo -e '\n'
done

