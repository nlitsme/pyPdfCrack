/*
 * A simple dictionary attack for cracking PKCS12 keys.
 *
 * This takes the salt + target value, and then tries all words read from stdin
 * as password.
 *
 * Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h> 
#include <sys/time.h>

void hexdump(const uint8_t *data, size_t n)
{
    while (n--)
        printf(" %02x", *data++);
}

int cvhex(char c)
{
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return c-'a'+10;
    if ('A'<=c && c<='F') return c-'A'+10;
    return -1;
}
int unhex(const char*str, uint8_t *data, int maxlen)
{
    uint8_t byte = 0;
    bool high = true;
    int count = 0;
    while (count < maxlen)
    {
        char c = *str++;
        if (!c)
            break;
        int x = cvhex(c);
        if (x>=0) {
            if (high)
                byte = x<<4;
            else {
                byte |= x;
                *data++ = byte;
                count++;
            }
            high = !high;
        }
    }
    return count;
}

int pw2unibuf(uint8_t *unipw, int maxlen, const char *pw)
{
    uint8_t *end = unipw+maxlen;
    int count = 0;
    while (unipw<end && *pw) {
        *unipw++ = 0; count++;
        *unipw++ = *pw++; count++;
    }
    *unipw++ = 0; count++;
    *unipw++ = 0; count++;

    return count;
}
void pkcsfill(uint8_t *dst, int dstlen, const uint8_t *src, int srclen)
{
    uint8_t *dstend = dst+dstlen;
    const uint8_t *p = src;
    const uint8_t *srcend = src+srclen;
    while (dst<dstend) {
        *dst++ = *p++;
        if (p==srcend)
            p = src;
    }
}
void genkey(const char *pwbuf, const uint8_t *salt, int saltlen, int keyid, int niter, uint8_t *digest)
{
    uint8_t saltbuf[SHA_CBLOCK];
    uint8_t passbuf[SHA_CBLOCK];

    uint8_t unipw[SHA_CBLOCK];

    int pwlen = pw2unibuf(unipw, sizeof(unipw), pwbuf);

    pkcsfill(saltbuf, sizeof(saltbuf), salt, saltlen);
    pkcsfill(passbuf, sizeof(passbuf), unipw, pwlen);

    uint8_t idbuf[SHA_CBLOCK];
    memset(idbuf, keyid, sizeof(idbuf));

    niter--;

    // start with special buf
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, idbuf, sizeof(idbuf));
    SHA1_Update(&ctx, saltbuf, sizeof(saltbuf));
    SHA1_Update(&ctx, passbuf, sizeof(passbuf));
    SHA1_Final(digest, &ctx);

    // rest just repeat sha-ing of the digest.
    while (niter--) {
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, digest, SHA_DIGEST_LENGTH);
        SHA1_Final(digest, &ctx);
    }
}



void rtrim(char *pw)
{
    int l = strlen(pw);
    char *p = pw+l-1;
    while (l && ( *p=='\n' || *p=='\r') )
    {
        *p-- = 0;
        l--;
    }
}
void report_speed(int count, double pct, char*pw)
{
    static uint64_t prev= 0;
    static struct timeval tprev;
    struct timeval now;
    gettimeofday(&now, 0);

    if (prev) {
        int64_t tdiff= ((int64_t)now.tv_sec-tprev.tv_sec)*1000000LL+((int64_t)now.tv_usec-tprev.tv_usec);
        double ips = 1000000.0 * double(count-prev)/double(tdiff);
        fprintf(stderr, "%10.2f keys/sec - %6.1f %%  cur=%10d: %s\r", ips, pct, count, pw);
    }

    prev = count;
    tprev = now;
}
void usage()
{
    printf("Usage: openssl_pass_crack -s SALT -k TARGETKEY -i KEYID -n ITER [-v] [range]\n");
    printf("   SALT, TARGETKEY are in hex digits\n");
    printf("   ITER is a number, e.g. 1024\n");
    printf("   KEYID is 1 for KEY, 2 for IV\n");
}
int main(int argc,char**argv)
{
    uint8_t salt[128] = {0};   int saltlen = 0;
    uint8_t targetkey[64] = {0};     int targetlen = 0;

    int totalkeys = 1;

    int niter = 0;
    int keyid = 0;
    bool verbose = false;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 's': saltlen = unhex(argv[++i], salt, sizeof(salt)); break;
            case 'k': targetlen = unhex(argv[++i], targetkey, sizeof(targetkey)); break;
            case 'i': keyid = strtoul(argv[++i], 0, 0); break;
            case 'n': niter = strtoul(argv[++i], 0, 0); break;
            case 'v': verbose = true; break;
            case 't': totalkeys = strtoul(argv[++i], 0, 0); break;
            default:
                      usage();
                      return 0;
        }
        else {
            usage();
            return 0;
        }
    }
    if (targetlen>SHA_DIGEST_LENGTH)
        targetlen = SHA_DIGEST_LENGTH;

    int count = 0;
    while (true) {
        char pwbuf[1024];
        if (NULL==fgets(pwbuf, 1024, stdin))
            break;
        rtrim(pwbuf);

        uint8_t out[SHA_DIGEST_LENGTH];
        genkey(pwbuf, salt, saltlen, keyid, niter, out);

        if (memcmp(out, targetkey, targetlen)==0) {
            printf("\n\nFOUND key: %s\n", pwbuf);
            break;
        }
        if (verbose && (count&0x3FFF)==0)
            report_speed(count, 100.0*double(count)/double(totalkeys), pwbuf);

        count++;
    }
    printf("\n");
}
