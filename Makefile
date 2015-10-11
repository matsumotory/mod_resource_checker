##
##  Makefile -- Build procedure for sample mod_resource_checker Apache module
##	  MATSUMOTO, Ryosuke
##

# target module source
TARGET=mod_resource_checker.c

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional user defines, includes and libraries
DEF=
INC=
LIB=-ljson
WC=-Wc,-std=c99

#   the default target
all: mod_resource_checker.so

#   compile the DSO file
mod_resource_checker.so: $(TARGET)
	$(APXS) -c $(DEF) $(INC) $(LIB) $(WC) $(TARGET)

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n 'resource_checker' .libs/mod_resource_checker.so

#   cleanup
clean:
	-rm -rf .libs *.o *.so *.lo *.la *.slo *.loT

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) -k start
restart:
	$(APACHECTL) -k restart
stop:
	$(APACHECTL) -k stop

test:
	git clone --recursive https://github.com/matsumoto-r/ab-mruby.git
	cd ab-mruby && make
	cd ab-mruby && ./ab-mruby -m ../test/check.rb -M ../test/test.rb http://127.0.0.1:8080/cgi-bin/loop.cgi
	grep "RCheckUCPU" /tmp/resource.log
	grep "RCheckSCPU" /tmp/resource.log
	grep "RCheckMEM" /tmp/resource.log
	grep "RCheckSTATUS" /tmp/resource.log

.PHONY: test
