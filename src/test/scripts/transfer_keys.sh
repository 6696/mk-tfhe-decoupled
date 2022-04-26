#################################################
# public keys transfer
rm -rf ./server

mkdir server
for i in 1 2 3 4
do
        mkdir -p server/client$i/keys 
        cp client$i/keys/KSKBSK.binary server/client$i/keys/KSKBSK.binary
        cp client$i/keys/Public.binary server/client$i/keys/Public.binary
done

#################################################

