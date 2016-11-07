/*
 * A simple performance test for openssl Triple-DES
 *
 * Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/des.h>

// 10000000 in 6.7 seconds
void hexdump(const uint8_t *data, size_t n)
{
    while (n--)
        printf(" %02x", *data++);
}
int main(int,char**argv)
{
    int m = strtol(argv[1],0,0);
    DES_cblock k1 = { 1 };
    DES_cblock k2 = { 2 };
    DES_cblock k3 = { 3 };

    for (int i=0 ; i<m ; i++) {
        DES_cblock  data = { 0 };
        DES_cblock  out = { 0 };
        DES_key_schedule ks1;  DES_set_key(&k1, &ks1);
        DES_key_schedule ks2;  DES_set_key(&k2, &ks2);
        DES_key_schedule ks3;  DES_set_key(&k3, &ks3);

        DES_ecb3_encrypt(&data, &out, &ks1, &ks2, &ks3, 0);
    }
}


