#!/usr/bin/env bash

eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=1.7 bash)"

pwd

go env
ip addr

ping  -c 5 ya.ru
ping6 -c 5 ya.ru
