/*
 * A simple performance test for openssl PKCS12 key generation
 *
 * Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

/*
clang++ -I/usr/local/Cellar/openssl/1.0.2j/include -L/usr/local/Cellar/openssl/1.0.2j/lib -std=c++1z -lcrypto openssl_tstpkcs12.cpp
*/

void hexdump(const uint8_t *data, size_t n)
{
    while (n--)
        printf(" %02x", *data++);
}
void dumperr()
{
    char buf[1024];
    while (unsigned long e= ERR_get_error()) {
        ERR_error_string_n(e, buf, 1024);
        printf("%08lx - %s\n", e, buf);
    }
}
void check(const char*tag, int rc)
{
    if (rc==1) return;
    printf("rc -> %d  %s\n", rc, tag);
    dumperr();
}
void check(const char*tag, uint8_t *rc)
{
    if (rc!=NULL) return;
    printf("rc -> NULL  %s\n", tag);
    dumperr();
}
int main(int,char**argv)
{
    int m = strtol(argv[1],0,0);

    SSL_load_error_strings();
    SSL_library_init();
    if (argv[2][0]=='2') {
        // 10000 in 1.446 seconds
        uint8_t salt2[] = { 0x68,0xe8,0xf7,0x78,0xef,0xe0,0xdb,0x98,0x45,0x35,0x32,0xb7,0xed,0xe8,0xe0,0xc0,0x98,0x30,0xec,0x81 };
        uint8_t key2[5];
        for (int i=0 ; i<m ; i++)
            PKCS12_key_gen_asc("test123", 7, salt2, sizeof(salt2), PKCS12_KEY_ID, 1024, sizeof(key2), key2, EVP_sha1());
    }
    else {
        // 10000 in 2.878 seconds
        uint8_t salt3[] = { 0x54,0x07,0xf1,0xed,0x84,0x89,0xf2,0x1c,0x86,0xea,0xf1,0x6e,0x54,0xdc,0x76,0xc3,0xef,0x19,0x3b,0x0c };
        uint8_t key3[24];
        for (int i=0 ; i<m ; i++)
            PKCS12_key_gen_asc("test123", 7, salt3, sizeof(salt3), PKCS12_KEY_ID, 1024, sizeof(key3), key3, EVP_sha1());
    }
}

