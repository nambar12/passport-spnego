PRODUCT = ../bin/gss-auth
C_SOURCES = gss-auth.c gss-misc.c base64.c

#INCLUDES = -I$(PWD)/krb5/usr/local/include
LIBS = -Wl,-rpath=../krb5_lib/ -L../krb5_lib -lgssapi_krb5 -lcom_err -lkrb5 -lkrb5support -lverto -lgssrpc -lk5crypto
# LIBS = -lgssapi_krb5 -lkrb5 -lkrb5support -lgssrpc -lk5crypto
GCC = /usr/bin/gcc

build:
	$(GCC) -g $(INCLUDES) $(LIBS) $(C_SOURCES) -o $(PRODUCT)

clean:
	rm -rf $(PRODUCT)
