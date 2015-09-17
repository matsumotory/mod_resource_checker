# mod_resource_checker.c

Process Resource Logging Module

##How To Compile
- Build
```
(optional) yum install json-c json-c-devel
make
```

- Add to  httpd.conf
```
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
    If you want JSON Format

    ```
    RCheckJSONFormat On
    ```
    
    ```
    { "msg": "RESOURCE_CHECKER", "time": "Sat Apr 27 00:37:41 2013", "type": "RCheckUCPU", "unit": "sec", "target_dir": "\/var\/www\/html\/", "src_ip": "192.168.12.10", "file": "\/var\/www\/html\/info.php", "request": "GET \/info.php HTTP\/1.1", "pid": 24045, "threshold": 0.000010, "result": 0.003000 }
    ```

    or below log format by default if no setting

    ```
    [Fri Apr 26 23:11:18 2013] pid=3225 RESOURCE_CHECKER: [ RCheckUCPU(sec) = 0.2969550000 (ALL) > threshold=(0.00001) ] config_dir=(/) src_ip=(192.168.12.1) access_file=(/usr/local/apache244/htdocs/blog/index.php) request=(GET /?p=3414 HTTP/1.0)
    ```

- Logging CPUUserTime
```
RCheckUCPU <threashould> <type>
```

- Logging CPUSystemTime
```
RCheckSCPU <threashould> <type>
```

- Logging UsedMemory
```
RCheckMEM <threashould> <type>

    <threashould>    digit(non-zero)

    <type>           ALL
                     SELF
                     CHILD
```

- Directory Access Control
```
<Directory "/var/www/html">
     RCheckUCPU 0.0001 ALL
</Directory>
```

- File Access Control
```
<Files "ag.cgi">
     RCheckUCPU 0.003 SELF
     RCheckSCPU 0.004 CHILD
     RCheckJSONFormat On
</Files>
```

- Files Regex Access Control
```
<FilesMatch ".*\.cgi$">
     RCheckUCPU 0.005 ALL
     RCheckMEM 1 ALL
</FilesMatch>
```

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php
