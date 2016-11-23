Русскоязычное описание ниже (Russian below).

English description:
Reverse-proxy server to handle https-requests. Requires existing http-server at the same server. By default `lets-proxy` handles
https requests to port 443 and proxies them as http to port 80 with same IP. It adds http header: X-Real-IP with ip address
of remote client and X-Forwarded-Proto=https - for https detection.

It has tcp mode, that doesn't parse traffic and proxy it as usual tcp-connection without modify.

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
Реверс-прокси сервер для обработки https-запросов. Для начала использования достаточно просто запустить его на сервере с 
запущенным http-сервером. При этом lets-proxy начнёт слушать порт 433 и передавать запросы на порт 80 с тем же IP-адресом.
К запросу будут добавляться заголовки X-Real-IP с IP-адресом источника запроса и X-Forwarded-Proto=https - для определения
что запрос пришел по https.

Есть режим tcp-прокси, в этом случае входящий трафик никак не анализируется и не меняется, а просто передается на указанный порт, но
уже в расшифрованном виде.

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
