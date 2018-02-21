[![Go Report Card](https://goreportcard.com/badge/github.com/rekby/lets-proxy)](https://goreportcard.com/report/github.com/rekby/lets-proxy)
[gocover](https://github.com/rekby/lets-proxy)

Русскоязычное описание ниже (Russian below).

English description
===================
A reverse-proxy server to handle https requests transparently. By default Lets-proxy handles
https requests to port 443 and proxies them as http to port 80 on the same IP address.

Lets-proxy adds the http headers, `X-Real-IP` which contains the IP address
of remote client and, `X-Forwarded-Proto=https`, for https detection. It obtains valid TLS certificates from Let's Encrypt and
handles https for free, in an automated way, including certificate renewal, and without warning in browsers.

Lets-proxy has a TCP mode, which doesn't parse traffic and proxies it as usual TCP connection without modification.

The program was created for shared hosting and can handle many thousands of domains per server. It is simple to implement and doesn't need settings to start the program on personal server/vps.

Since lets encrypt disable TLS-SNI validation for create new certificates - lets-proxy need handle http-traffic for directory /.well-known/acme-challenge/ of certificated domain. Now it can proxy by server config or scripts to http://127.0.0.1:4443/.well-known/acme-challenge/ (bind address can be changed by arg --bind-http-validation-to). 

[Http-01 validation guide](https://github.com/rekby/lets-proxy/wiki/Proxy-http-01-validation).

Quick start:

    ./lets-proxy or lets-proxy.exe
    
Install for autostart (daemon for linux or windows-service for linux)
    
    ./lets-proxy --service-name=lets-proxy --service-action=install
    lets-proxy.exe --service-name=lets-proxy --service-action=install
    

Remove from autostart

    ./lets-proxy --service-name=lets-proxy --service-action=uninstall
    lets-proxy.exe --service-name=lets-proxy --service-action=uninstall

Use --help key for details:

    ./lets-proxy --help or lets-proxy.exe --help


Русский (Russian):
==================

Реверс-прокси сервер для прозрачной обработки https-запросов. Для начала использования достаточно просто запустить его на сервере с 
запущенным http-сервером. При этом lets-proxy начнёт слушать порт 433 и передавать запросы на порт 80 с тем же IP-адресом.
К запросу будут добавляться заголовки X-Real-IP с IP-адресом источника запроса и X-Forwarded-Proto=https - для определения
что запрос пришел по https. Сертификаты для работы https получаются в реальном времени от letsencrypt.org. Это правильные
(не самоподписанные) бесплатные сертификаты, которым браузеры доверяют.

Есть режим tcp-прокси, в этом случае входящий трафик никак не анализируется и не меняется, а просто передается на указанный порт, но
уже в расшифрованном виде.

Программа разрабатывается для использования на виртуальном хостинге и может работать с тысячами доменов на каждом сервере.
С другой стороны она проста и не требует начальных настроек для запуска на персональном сервере.

С момента отключения Lets encrypt варианта проверки домена через tls-sni для работы lets-proxy требуется обработка в lets-proxy проверочного http-трафика. Через настройки сервера или скрипты нужно передавать запросы к папке "/.well-known/acme-challenge/" обслуживаемых доменов на внутренний обработчик валидации lets-proxy: http://127.0.0.1:4443/.well-known/acme-challenge/ (адрес привязки может быть изменен параметром --bind-http-validation-to).

[Инструкция по настройке проверок http-01](https://github.com/rekby/lets-proxy/wiki/Proxy-http-01-validation).

Быстрый старт:

    ./lets-proxy или lets-proxy.exe

Установить в автозапуск (домен в linux, служба в windows)
    
    ./lets-proxy --service-name=lets-proxy --service-action=install
    lets-proxy.exe --service-name=lets-proxy --service-action=install
    

Удалить из автозапуска

    ./lets-proxy --service-name=lets-proxy --service-action=uninstall
    lets-proxy.exe --service-name=lets-proxy --service-action=uninstall

Для получения подробной справки воспользуйтесь --help:

    ./lets-proxy --help or lets-proxy.exe --help


Used libraries (alphabet ordered):
==================================

* http://github.com/hashicorp/golang-lru - memory cache
* http://github.com/hlandau/acme/acmeapi - used for work with lets encrypt
* http://github.com/kardianos/service - working as service, especially for windows.
* http://github.com/miekg/dns - direct dns requests, IDN decode
* http://github.com/sevlyar/go-daemon - unix daemonize
* http://github.com/Sirupsen/logrus - logging
* http://gopkg.in/natefinch/lumberjack.v2 - log rotate
