/**      XTEA3.C by Oleg Plotnikov                                         **/
/**      XTEA-3 by Tom St Denis implementation for C programmers           **/
/**      XTEA-3 encrypts 128 bit block with 256 bit key                    **/
/**      XTEA-3 is based on original TEA, but with large key and block     **/
/**      It seems to be much secure version                                **/
/**      Implemented by Alexander Myasnikov                                **/
/**      WEB:       www.darksoftware.narod.ru                              **/

#include <stdlib.h>
#include <mem.h>

typedef unsigned long u32;

u32 key[8];

const u32 ITERATIONS = 32;

#define rol(N, R) _lrotl(N, R)


void __stdcall __export
crypt (u32 * plain)
{
  u32 a, b, c, d, sum, r, t;

  sum = 0;
  a = plain[0] + key[0];
  b = plain[1] + key[1];
  c = plain[2] + key[2];
  d = plain[3] + key[3];
  for (r = 0; r != ITERATIONS; r++)
    {
      a = a + (((b << 4) + rol (key[(sum % 4) + 4], b)) ^
	       (d + sum) ^ ((b >> 5) + rol (key[sum % 4], b >> 27)));
      sum = sum + 0x9E3779B9;
      c = c + (((d << 4) + rol (key[((sum >> 11) % 4) + 4], d)) ^
	       (b + sum) ^ ((d >> 5) + rol (key[(sum >> 11) % 4], d >> 27)));

      t = a;
      a = b;
      b = c;
      c = d;
      d = t;
    }
  plain[0] = a ^ key[4];
  plain[1] = b ^ key[5];
  plain[2] = c ^ key[6];
  plain[3] = d ^ key[7];
}


void __stdcall __export
decrypt (u32 * plain)
{
  u32 a, b, c, d, delta, sum, t;
  long r;

  delta = 0x9E3779B9;
  sum = delta * ITERATIONS;

  d = plain[3] ^ key[7];
  c = plain[2] ^ key[6];
  b = plain[1] ^ key[5];
  a = plain[0] ^ key[4];


  for (r = ITERATIONS - 1; r != -1; r--)
    {

      t = d;
      d = c;
      c = b;
      b = a;
      a = t;

      c = c - (((d << 4) + rol (key[((sum >> 11) % 4) + 4], d)) ^
	       (b + sum) ^ ((d >> 5) + rol (key[(sum >> 11) % 4], d >> 27)));

      sum = sum - 0x9E3779B9;

      a = a - (((b << 4) + rol (key[(sum % 4) + 4], b)) ^
	       (d + sum) ^ ((b >> 5) + rol (key[sum % 4], b >> 27)));

    }


  plain[3] = d - key[3];
  plain[2] = c - key[2];
  plain[1] = b - key[1];
  plain[0] = a - key[0];

}


void __stdcall __export
setup (u32 * k)
{
  memcpy (&key[0], &k[0], 32);
}
