# mod_resource_checker [![Build Status](https://travis-ci.org/matsumoto-r/mod_resource_checker.svg?branch=master)](https://travis-ci.org/matsumoto-r/mod_resource_checker)

Process Resource Logging Module using JSON format into file or piped program.

Supported apache2.2.x and apache2.4.x with prefork mpm.

```
tail -n 1 /path/to/resource.log | jq .
```

```json
{
  "result": {
    "RCheckMEM": 39.011719,
    "RCheckSCPU": 0.06999,
    "RCheckUCPU": 0.687896
  },
  "response_time": 0,
  "threshold": null,
  "pid": 19748,
  "scheme": "http",
  "filename": "/usr/local/apache244/htdocs/blog/index.php",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": null,
  "type": "RCheckALL",
  "date": "Sun Oct 11 16:10:42 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "blog.matsumoto-r.jp",
  "server_ip": "127.0.0.1",
  "uri": "/index.php",
  "uid": 2,
  "size": 418,
  "content_length": 2498,
  "status": 200
}

```

##How To Compile
- Build
```
(optional) yum install json-c json-c-devel
make
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


### Directive Config
- Output Format

```json
{
  "module": "mod_request_checker",
  "date": "Thu Sep 17 11:48:57 2015",
  "type": "RCheckMEM",
  "unit": "MiB",
  "response_time": 5,
  "location": "/path/to/",
  "remote_ip": "192.168.0.1",
  "filename": "/path/to/phpinfo.php",
  "scheme": "http",
  "method": "GET",
  "hostname": "test001.example.jp",
  "uri": "/phpinfo.php",
  "uid": 929643,
  "status": 200,
  "size": 20,
  "pid": 3220,
  "threshold": 0.1,
  "result": 2.597656
}
```

- Logging all status and resources log

```apache
RCheckALL On
```

```json
{
  "result": {
    "RCheckMEM": 39.011719,
    "RCheckSCPU": 0.06999,
    "RCheckUCPU": 0.687896
  },
  "response_time": 0,
  "threshold": null,
  "pid": 19748,
  "scheme": "http",
  "filename": "/usr/local/apache244/htdocs/blog/index.php",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": null,
  "type": "RCheckALL",
  "date": "Sun Oct 11 16:10:42 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "blog.matsumoto-r.jp",
  "server_ip": "127.0.0.1",
  "uri": "/index.php",
  "uid": 2,
  "size": 418,
  "content_length": 2498,
  "status": 200
}
```

- Logging all request which don't include resouces data

```apache
RCheckSTATUS On
```

```json
{
  "result": 0,
  "response_time": 0,
  "scheme": "http",
  "filename": "/var/www/html/index.html",
  "remote_ip": "127.0.0.1",
  "location": "/",
  "unit": "null",
  "type": "RCheckSTATUS",
  "date": "Fri Oct 09 15:43:26 2015",
  "module": "mod_resource_checker",
  "method": "GET",
  "hostname": "127.0.0.1",
  "uri": "/index.html",
  "uid": 0,
  "size": 7,
  "status": 200,
  "pid": 20572,
  "threshold": 0
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
