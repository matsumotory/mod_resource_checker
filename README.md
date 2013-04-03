# mod_resource_checker.c
Process Resource Logging Module by rusage() By matsumoto_r Sep 2009 in Japan

- Date     2009/12/08
- Version  0.01-beta

```
change log
2009/12/08 matsumoto_r coding start
```

##How To Compile
### Use DSO
```
apxs -c -D__MOD_APACHE2__ mod_resource_checker.c
cp ./.libs/mod_resource_checker.so /usr/local/apache2/modules
```

### add to  httpd.conf
```
LoadModule resource_checker_module libexec/mod_resource_checker.so
```


##How To Use
### Server Config
nothing

### Directive Config

     log file: /tmp/mod_resource_checker.log
           or #define MOD_RESOURCE_CHECKER_LOG_FILE "/tmp/mod_resource_checker.log"

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
</Files>
```

- Files Regex Access Control
```
<FilesMatch ".*\.cgi$">
     RCheckUCPU 0.005 ALL
</FilesMatch>
```

