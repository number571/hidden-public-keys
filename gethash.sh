PUBKEY=$(curl -s 'http://localhost:9572/api/service/pubkey')
echo -n "sha256: "
echo -n $PUBKEY | sha256sum | awk '{ print $1 }';
echo -n "sha384: "
echo -n $PUBKEY | sha384sum | awk '{ print $1 }';
echo -n "sha512: "
echo -n $PUBKEY | sha512sum | awk '{ print $1 }';
