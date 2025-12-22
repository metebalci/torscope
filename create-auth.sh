#!/bin/bash
#
# This script creates the files necessary for client authorization. If files already exist, they are not overwritten.
#
# - A private key in PEM format is created as a temporary file.
# - Then, its base32 format is created to be used with torscope.
# - Then, its public key in auth format (base32) is created. This should be used in hidden service.
# - Then, the private key in PEM format is deleted.
#

set -eu

if [ $# -ne 1 ]; then
	echo "Usage: create-auth.sh username"
	exit 1
fi

if [ -f "$1.pri" ]; then
	echo "$1.pri already exists."
	exit 1
fi

if [ -f "$1.auth" ]; then
	echo "$1.auth already exists."
	exit 1
fi

# create private key
PRVPEM=$(mktemp)
openssl genpkey -algorithm x25519 -out "$PRVPEM"

# convert private key to auth format
cat "$PRVPEM" | grep -v " PRIVATE KEY" | base64pem -d | tail --bytes=32 | base32 | sed 's/=//g' > "$1.pri"

# convert public key to auth format
echo -n "descriptor:x25519:" > "$1.auth"
openssl pkey -in "$PRVPEM" -pubout | grep -v " PUBLIC KEY" | base64pem -d | tail --bytes=32 | base32 | sed 's/=//g' >> "$1.auth"

rm -f "$PRVPEM"

echo "DONE: $1.pri and $1.auth are created."
echo "You should copy $1.auth to the onion service's <HiddenServiceDir>/authorized_clients/ folder and add 'HiddenServiceAuthorizeClient $1' to the torrc."
echo "You should use torscope with --auth-key-file $1.pri."
