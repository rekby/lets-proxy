#!/usr/bin/env bash

#yum install -y iproute

eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=1.7 bash)"

pwd
#ip addr
ping6 -c 3 ifconfig.io

export GOPATH=/gopath
mkdir -p ${GOPATH}/src/github.com/rekby/lets-proxy
cp -R ./ ${GOPATH}/src/github.com/rekby/lets-proxy/

#go build -o http-ok gitlab/http-ok.go
go build -o http-headers gitlab/http-headers.go
./http-headers &
sleep 1

echo "Test http-headers: "
curl -s http://localhost 2>/dev/null
echo
echo

DOMAIN="gitlab-test.1gb.ru"

TMP_SUBDOMAIN="tmp-`date +%Y-%m-%d--%H-%M-%S`--$RANDOM$RANDOM.ya"
TMP_DOMAIN="$TMP_SUBDOMAIN.$DOMAIN"

echo "Tmp domain: $TMP_DOMAIN"

curl -L https://github.com/rekby/ypdd/releases/download/v0.2/ypdd-linux-amd64.tar.gz > ypdd-linux-amd64.tar.gz 2>/dev/null
tar -zxvf ypdd-linux-amd64.tar.gz

MY_IPv6=`curl -s6 http://ifconfig.io/ip 2>/dev/null`
echo MY IPv6: ${MY_IPv6}
./ypdd --sync ${DOMAIN} add ${TMP_SUBDOMAIN} AAAA ${MY_IPv6}

go build -o proxy github.com/rekby/lets-proxy

./proxy --test &
#./proxy &  ## REAL CERT. WARNING - LIMITED CERT REQUEST

sleep 10 # Allow to start, generate keys, etc.

TEST=`curl -vsk https://${TMP_DOMAIN}`

echo "Delete record"
ID=`./ypdd ${DOMAIN} list | grep ${TMP_SUBDOMAIN} | cut -d ' ' -f 1`
echo "ID: $ID"
./ypdd $DOMAIN del $ID

( echo "$TEST" | grep -q "HOST:" && echo OK ) || ( echo FAIL && exit 1)

echo -n "Test cache file exists: "
if grep -q CERTIFICATE certificates/${TMP_DOMAIN}.crt && grep -q PRIVATE certificates/${TMP_DOMAIN}.key; then
    echo "OK"
else
    echo "FAIL"
    echo
    echo certificates/${TMP_DOMAIN}.crt
    cat certificates/${TMP_DOMAIN}.crt
    echo
    echo certificates/${TMP_DOMAIN}.key
    cat certificates/${TMP_DOMAIN}.key
    exit 1
fi
