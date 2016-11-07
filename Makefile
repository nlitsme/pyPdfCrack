APPS=openssl_tstpkcs12 mbedtls_tstpkcs12 openssl_rc2_crack openssl_sha1_perftest openssl_pkcs12_perftest openssl_des3_perftest openssl_pass_crack PdfEncryptionTest.class
all: $(APPS)

CXX=clang++
sslflags=-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lssl
mbedflags=-I /usr/local/include/ -L/usr/local/lib -lmbedcrypto
cflags=-g -std=c++1z -Wall -O3

mbedtls_tstpkcs12: mbedtls_tstpkcs12.cpp
	$(CXX) $^ -o $@ $(mbedflags) $(cflags)
openssl_tstpkcs12: openssl_tstpkcs12.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

openssl_rc2_crack: openssl_rc2_crack.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

openssl_sha1_perftest: openssl_sha1_perftest.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

openssl_pkcs12_perftest: openssl_pkcs12_perftest.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

openssl_des3_perftest: openssl_des3_perftest.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

openssl_pass_crack: openssl_pass_crack.cpp
	$(CXX) $^ -o $@ $(sslflags) $(cflags)

clean:
	$(RM) $(APPS)
	$(RM) -r $(wildcard *.dSYM)

BC=$(HOME)/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.49/bcprov-jdk15on-1.49.jar:$(HOME)/.m2/repository/org/bouncycastle/bcpkix-jdk15on/1.49/bcpkix-jdk15on-1.49.jar
ITEXT=$(HOME)/gitprj/itext7
PdfEncryptionTest.class: PdfEncryptionTest.java
	javac -classpath "$(ITEXT)/target/*:$(BC)" PdfEncryptionTest.java

runjava:
	java -classpath ".:$(ITEXT)/target/*:$(BC)" PdfEncryptionTest
 
