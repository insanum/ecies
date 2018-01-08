
CC=clang
CFLAGS=-Wall

OSSL_ARGS=$(CFLAGS) \
	  -I/usr/local/opt/openssl/include \
	  -L/usr/local/opt/openssl/lib
OSSL_SRC=ecies_openssl.c
OSSL_BIN=ossl

WSSL_ARGS=$(CFLAGS)
WSSL_SRC=ecies_wolfssl.c
WSSL_BIN=wssl

all:
	$(CC) -o $@ $(OSSL_ARGS)  -lcrypto  -o $(OSSL_BIN)  $(OSSL_SRC)
	$(CC) -o $@ $(WSSL_ARGS)  -lwolfssl -o $(WSSL_BIN)  $(WSSL_SRC)

cert:
	openssl ecparam -name prime256v1 -noout -genkey -conv_form uncompressed -outform DER -out ecc_key.der

clean:
	rm -f ossl wssl

