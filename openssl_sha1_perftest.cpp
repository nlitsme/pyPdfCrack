/*
 * A simple performance test for openssl SHA1 hash iteration
 *
 * Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

// -> 10000000 iterations in 1.8 seconds
//     -> 43400 genkey iterations / sec
void hexdump(const uint8_t *data, size_t n)
{
    while (n--)
        printf(" %02x", *data++);
}
int main(int,char**argv)
{
    int m = strtol(argv[1],0,0);
    SHA_CTX ctx;
    uint8_t data[20] = {0};

    for (int i=0 ; i<m ; i++) {
        SHA_Init(&ctx);
        SHA_Update(&ctx, data, 20);
        SHA_Final(data, &ctx);
    }
}

