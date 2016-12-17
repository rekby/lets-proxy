#!/usr/bin/env bash
#yum install -y iproute

echo "install golang"

eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=1.7 bash)"

pwd
#ip addr
ping6 -c 3 ifconfig.io

export GOPATH=/gopath
mkdir -p ${GOPATH}/src/github.com/rekby/lets-proxy
cp -R ./ ${GOPATH}/src/github.com/rekby/lets-proxy/

echo "Go test"
go test -v github.com/rekby/lets-proxy || exit 1

go build -o http-headers gitlab/http-headers.go
./http-headers &
sleep 1

echo "Test http-headers: "
curl -s http://localhost 2>/dev/null
echo
echo

DOMAIN="gitlab-test.1gb.ru"
RND="${RANDOM}"
TMP_SUBDOMAIN="tmp-`date +%Y-%m-%d--%H-%M-%S`--${RND}--1.ya"
TMP_SUBDOMAIN2="tmp-`date +%Y-%m-%d--%H-%M-%S`--${RND}--2.ya"
TMP_WWWSUBDOMAIN2="www.${TMP_SUBDOMAIN2}"
TMP_SUBDOMAIN3WWWONLY_WITHOUT_WWW="tmp-`date +%Y-%m-%d--%H-%M-%S`--${RND}--3.ya"
TMP_SUBDOMAIN3WWWONLY="www.${TMP_SUBDOMAIN3WWWONLY_WITHOUT_WWW}"

TMP_DOMAIN="$TMP_SUBDOMAIN.$DOMAIN"
TMP_DOMAIN2="$TMP_SUBDOMAIN2.$DOMAIN"
TMP_WWWDOMAIN2="$TMP_WWWSUBDOMAIN2.$DOMAIN"
TMP_DOMAIN3WWWONLY_WITHOUT_WWW="$TMP_SUBDOMAIN3WWWONLY_WITHOUT_WWW.$DOMAIN"
TMP_DOMAIN3WWWONLY="$TMP_SUBDOMAIN3WWWONLY.$DOMAIN"

echo "Tmp domain: $TMP_DOMAIN"

curl -L https://github.com/rekby/ypdd/releases/download/v0.2/ypdd-linux-amd64.tar.gz > ypdd-linux-amd64.tar.gz 2>/dev/null
tar -zxvf ypdd-linux-amd64.tar.gz

MY_IPv6=`curl -s6 http://ifconfig.io/ip 2>/dev/null`
echo MY IPv6: ${MY_IPv6}
./ypdd --sync ${DOMAIN} add ${TMP_SUBDOMAIN} AAAA ${MY_IPv6}
./ypdd --sync ${DOMAIN} add ${TMP_SUBDOMAIN2} AAAA ${MY_IPv6}
./ypdd --sync ${DOMAIN} add ${TMP_WWWSUBDOMAIN2} AAAA ${MY_IPv6}
./ypdd --sync ${DOMAIN} add ${TMP_SUBDOMAIN3WWWONLY} AAAA ${MY_IPv6}

function delete_domain(){
    echo "Delete record"
    ID=`./ypdd ${DOMAIN} list | grep ${TMP_SUBDOMAIN} | cut -d ' ' -f 1`
    echo "ID: $ID"
    ./ypdd $DOMAIN del $ID

    echo "Delete record-2"
    ID=`./ypdd ${DOMAIN} list | grep ${TMP_SUBDOMAIN2} | cut -d ' ' -f 1`
    echo "ID: $ID"
    ./ypdd $DOMAIN del $ID

    echo "Delete record-2-www"
    ID=`./ypdd ${DOMAIN} list | grep ${TMP_WWWSUBDOMAIN2} | cut -d ' ' -f 1`
    echo "ID: $ID"
    ./ypdd $DOMAIN del $ID

    echo "Delete record-3-www-only"
    ID=`./ypdd ${DOMAIN} list | grep ${TMP_SUBDOMAIN3WWWONLY} | cut -d ' ' -f 1`
    echo "ID: $ID"
    ./ypdd $DOMAIN del $ID
}

function exit_error(){
    echo "DELETE TMP DOMAINS"
    delete_domain

    echo "LOG"
    cat log.txt
    exit 1
}


go build -o proxy github.com/rekby/lets-proxy

function restart_proxy(){
    PID=`cat lets-proxy.pid`
    if [ -n "$PID" ]; then
        kill -9 "$PID"
    fi
    ./proxy --test --logout=log.txt --loglevel=debug --real-ip-header=remote-ip,test-remote --additional-headers=https=on,protohttps=on,X-Forwarded-Proto=https --connection-id-header=Connection-ID --cert-json --daemon --pid-file=lets-proxy.pid
    sleep 10 # Allow to start, generate keys, etc.
}

function flush_cache(){
    PIDFILE="lets-proxy.pid"
    PID=`cat ${PIDFILE}`
    if [ -n "$PID" ]; then
        if ! kill -SIGHUP "$PID"; then
            echo "PID FAILED"
            echo "PIDFILE: ${PIDFILE}"
            echo "PID: ${PID}"

            echo "Process list"
            ps aux

            exit_error
        fi
    fi
    sleep 1

}
restart_proxy

echo "Check PID"
flush_cache
flush_cache

TEST=`curl -vsk https://${TMP_DOMAIN}`

echo "${TEST}"

function test_or_exit(){
    FULLTEXT="${TEST}"

    NAME="$1"
    SUBSTRING="$2"

    if echo "${FULLTEXT}" | grep -qi "${SUBSTRING}"; then
        echo "${NAME}-OK"
        return
    else
        echo "${NAME}-FAIL"
        exit_error
    fi

}

test_or_exit "HOST" "HOST: ${TMP_DOMAIN}"
test_or_exit "remote-ip" "remote-ip: ${MY_IPv6}"
test_or_exit "test-remote" "test-remote: ${MY_IPv6}"
test_or_exit "https" "https: on"
test_or_exit "protohttps" "protohttps: on"
test_or_exit "X-Forwarded-Proto" "X-Forwarded-Proto: https"
test_or_exit "Connection-ID" "Connection-ID: "

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
    exit_error
fi

echo "Test install proxy"
./proxy --test --service-name=lets-proxy --service-action=install
./proxy --test --service-name=lets-proxy --service-action=reinstall

find /etc -name '*lets-proxy*'

./proxy --test --service-name=lets-proxy --service-action=uninstall


echo "Test obtain only one cert for every domain same time and test www-optimization"
echo > log.txt

for i in `seq 1 10`; do
    A=`curl -k https://${TMP_DOMAIN2} >/dev/null 2>&1 &`
    A=`curl -k https://${TMP_WWWDOMAIN2} >/dev/null 2>&1 &`
done
curl -k https://${TMP_DOMAIN2} >/dev/null 2>&1 # Wait answer

CERTS_OBTAINED=`cat log.txt | grep "BEGIN CERTIFICATE" | wc -l`
if [ "${CERTS_OBTAINED}" != "1" ]; then
    echo "Must be only one cert obtained. But obtained: ${CERTS_OBTAINED}"
    exit_error
fi
echo "Obtain only one cert for a domain same time - OK"
sleep 3 # For more readable logs

echo "Test www-optimiation"
TEST=`curl -k https://${TMP_WWWDOMAIN2} 2>/dev/null` # Domain work
test_or_exit "HOST" "HOST: ${TMP_WWWDOMAIN2}"

# Have metadata
cat certificates/${TMP_DOMAIN2}.json
if ! ( grep -q ${TMP_WWWDOMAIN2} certificates/${TMP_DOMAIN2}.json && grep -q ${TMP_WWWDOMAIN2} certificates/${TMP_DOMAIN2}.json ); then
    exit_error
fi

echo
echo "Check www-only domain"
TEST=`curl -sk https://${TMP_DOMAIN3WWWONLY}`
test_or_exit "HOST" "HOST: ${TMP_DOMAIN3WWWONLY}"
if ! [ -e certificates/${TMP_DOMAIN3WWWONLY_WITHOUT_WWW}.crt ] || ! grep -q ${TMP_DOMAIN3WWWONLY} certificates/${TMP_DOMAIN3WWWONLY_WITHOUT_WWW}.json; then
    echo
    cat certificates/${TMP_DOMAIN3WWWONLY_WITHOUT_WWW}.crt
    echo
    cat certificates/${TMP_DOMAIN3WWWONLY_WITHOUT_WWW}.json

    exit_error
fi

echo
echo "Try lock working domain and request it with exited cert"
touch certificates/${TMP_DOMAIN}.lock
flush_cache

TEST=`curl -sk https://${TMP_DOMAIN}`
test_or_exit "HOST" "HOST: ${TMP_DOMAIN}"

echo "Remove existed certificate"
rm -rf certificates/${TMP_DOMAIN}{.crt,.key}
flush_cache
TEST=`curl -sk https://${TMP_DOMAIN}` # must be empty becouse lets-proxy must return error
if [ -n "${TEST}" ]; then
    echo "Obtain cert for locked domain"
    echo "${TEST}"

    echo
    ls -la certificates/

    exit_error
fi

delete_domain

