/*
 * A simple brute force RC2 cracker.
 *
 * Trying all 40 bit values in about 1.5 days on my 2013 macbookpro
 */
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rc2.h>
#include <time.h> 
#include <sys/time.h>

// -> 1000000 iterations in 0.8 seconds
//
//  the test key:
// ./openssl_rc2_crack -e 43036642daa47c52 -p 2203ef501040eba0 -f 0x6896000000 -t 0x6896300000 -v
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
bool unhex(const char*str, uint8_t *data, int n)
{
    uint8_t byte = 0;
    bool high = true;
    while (n>0)
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
                n--;
            }
            high = !high;
        }
    }
    return n==0;
}
void report_speed(uint64_t count, double pct)
{
    static uint64_t prev= 0;
    static struct timeval tprev;
    struct timeval now;
    gettimeofday(&now, 0);

    if (prev) {
        int64_t tdiff= ((int64_t)now.tv_sec-tprev.tv_sec)*1000000LL+((int64_t)now.tv_usec-tprev.tv_usec);
        double ips = 1000000.0 * double(count-prev)/double(tdiff);
        fprintf(stderr, "%10.2f keys/sec - %6.1f %%  cur=%010llx\r", ips, pct, count);
    }

    prev = count;
    tprev = now;
}
int main(int argc,char**argv)
{
    uint8_t plain[8];
    uint8_t encrypted[8];

    uint64_t from= 0;
    uint64_t until= 0x10000000000;
    bool verbose = false;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 'e': unhex(argv[++i], encrypted, 8); break;
            case 'p': unhex(argv[++i], plain, 8); break;
            case 'f': from = strtoul(argv[++i], 0, 0); break;
            case 't': until = strtoul(argv[++i], 0, 0); break;
            case 'v': verbose = true; break;
        }
    }

    RC2_KEY key;
    uint8_t pw[8] = {0};
    uint8_t out[8] = {0};

    uint64_t plain_num = *(uint64_t*)plain;
    printf("enc=%016llx  dec=%016llx\n", *(uint64_t*)encrypted, plain_num);
    for (uint64_t i=from ; i<until ; i++) {
        *(uint64_t*)pw = i;
        RC2_set_key(&key, 5, pw, 40);
        RC2_ecb_encrypt(encrypted, out, &key, RC2_DECRYPT);
        if (*(uint64_t*)out == plain_num) {
            printf("\n\nFOUND key: %010llx\n", i);
            break;
        }

        if (verbose && (i&0xFFFFF)==0)
            report_speed(i, 100.0*double(i-from)/double(until-from));
    }
    printf("\n");
}
