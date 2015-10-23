# mod_resource_checker [![Build Status](https://travis-ci.org/matsumoto-r/mod_resource_checker.svg?branch=master)](https://travis-ci.org/matsumoto-r/mod_resource_checker)

Process Resource Logging Module using JSON format into file or piped program.

Supported apache2.2.x and apache2.4.x with prefork mpm.

[rcheck-analyze](https://github.com/matsumoto-r/rcheck-analyzer) is analyze tool for mod_resource_checker log.
　

- setup `conf.d/mod_resource_checker.conf`

```apache
LoadModule resource_checker_module modules/mod_resource_checker.so

RCheckLogPath /var/log/httpd/resoruce.log
RCheckRealServerName www.matsumoto-r.jp

<Location />
  RCheckALL On
</Location>
```

- check log file 

```
tail -n 1 /var/log/httpd/resoruce.log | jq .
```

- output logs

```json
{
  "result": {
    "RCheckMEM": 39.023438,
    "RCheckSCPU": 0.055992,
    "RCheckUCPU": 0.481926
  },
  "response_time": 0,
  "threshold": null,
  "pid": 22533,
  "status": 200,
  "scheme": "http",
  "filename": "/usr/local/apache244/htdocs/blog/index.php",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": null,
  "type": "RCheckALL",
  "date": "Sun Oct 11 18:08:12 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "blog.matsumoto-r.jp",
  "server_ip": "127.0.0.1",
  "uri": "/index.php",
  "real_server_name": "www.matsumoto-r.jp",
  "uid": 2,
  "size": 418,
  "content_length": 2498
}
```

##How To Compile
- Build
```
(optional) yum install json-c json-c-devel
make
suod make install
```

- Add to  httpd.conf
```apache
LoadModule resource_checker_module modules/mod_resource_checker.so
```


##How To Use
### Server Config
- log file name (default /tmp/mod_resource_checker.log if no setting)

    ```
    RCheckLogPath "/usr/local/apache/logs/resoruce.log"
    ```

    or

- if enable JSON Format `RCheckJSONFormat On`, for exmaple,

    ```
    RCheckLogPath "| mongoimport -d apache -c resource_check"
    ```

    It's very cool.

- logging real server name

```
RCheckRealServerName www.matsumoto-r.jp
```

### Directive Config
- Logging all status and resources log

```apache
<Location />
  RCheckALL On
</Location>
```

```json
{
  "result": {
    "RCheckMEM": 39.023438,
    "RCheckSCPU": 0.055992,
    "RCheckUCPU": 0.481926
  },
  "response_time": 0,
  "threshold": null,
  "pid": 22533,
  "status": 200,
  "scheme": "http",
  "filename": "/usr/local/apache244/htdocs/blog/index.php",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": null,
  "type": "RCheckALL",
  "date": "Sun Oct 11 18:08:12 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "blog.matsumoto-r.jp",
  "server_ip": "127.0.0.1",
  "uri": "/index.php",
  "real_server_name": "www.matsumoto-r.jp",
  "uid": 2,
  "size": 418,
  "content_length": 2498
}
```

- Logging all request which don't include resouces data

```apache
<Location />
  RCheckSTATUS On
</Location>
```

```json
{
  "result": 0,
  "response_time": 0,
  "threshold": null,
  "pid": 22533,
  "status": 200,
  "scheme": "http",
  "filename": "/usr/local/apache244/htdocs/blog/index.php",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": null,
  "type": "RCheckSTATUS",
  "date": "Sun Oct 11 18:08:12 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "blog.matsumoto-r.jp",
  "server_ip": "127.0.0.1",
  "uri": "/index.php",
  "real_server_name": "www.matsumoto-r.jp",
  "uid": 2,
  "size": 418,
  "content_length": 2498
}
```

- Logging CPUUserTime

```apache
RCheckUCPU <threashould> <type>
```

- Logging CPUSystemTime
```apache
RCheckSCPU <threashould> <type>
```

- Logging UsedMemory
```apache
RCheckMEM <threashould> <type>

    <threashould>    digit(non-zero)

    <type>           ALL
                     SELF
                     CHILD
```

- Directory Access Control
```apache
<Directory "/var/www/html">
     RCheckUCPU 0.0001 ALL
</Directory>
```

- File Access Control
```apache
<Files "ag.cgi">
     RCheckUCPU 0.003 SELF
     RCheckSCPU 0.004 CHILD
     RCheckJSONFormat On
</Files>
```

- Files Regex Access Control
```apache
<FilesMatch ".*\.cgi$">
     RCheckUCPU 0.005 ALL
     RCheckMEM 1 ALL
</FilesMatch>
```

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php
