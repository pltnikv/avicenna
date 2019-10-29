/*                      Avicena

/*                      Oleg Plotnikov                                      */
/*                                                                                 */


#include <mem.h>

typedef unsigned long long u64;
typedef unsigned long u32;

const u64 EXTENDED_KEY_SCHEDULE_CONST = 6148914691236517205L;

u32 SUBKEY_INTERVAL = 4;

u32 PI16[16] = { 0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1 };

u32 RPI16[16] = { 0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7 };

u32 DEPTH_OF_D_IN_R = 8;

u32 R16[8][8] = {
  {55, 43, 37, 40, 16, 22, 38, 12},
  {25, 25, 46, 13, 14, 13, 52, 57},
  {33, 8, 18, 57, 21, 12, 32, 54},
  {34, 43, 25, 60, 44, 9, 59, 34},
  {28, 7, 47, 48, 51, 9, 35, 41},
  {17, 6, 18, 25, 43, 42, 40, 15},
  {58, 7, 32, 45, 19, 18, 2, 56},
  {47, 49, 27, 58, 37, 48, 53, 56},
};


u64 t[3];
u64 x[2];
u64 y[2];

u32 nr = 80;                    // number of rounds depending on block size

u64 k[17];                      // initial key words including knw
u32 nw = 16;                    // number of key words excluding knw

u64 vd[16];
u64 ed[16];
u64 fd[16];
u64 ksd[16];

#define rol64(x, n)    ((x << (n)) | (x >> (64 - n)))

#define ror64(x, n)    (x >> n) | (x << (64 - n))

#define mix(j,d)\
\
  y[0] = x[0] + x[1];\
  y[1] = rol64 (x[1], R16[(d) % DEPTH_OF_D_IN_R][(j)]);\
  y[1] ^= y[0];\

#define demix(j,d)\
   y[1] ^= y[0];\
   x[1]  = ror64(y[1], R16[(d) % DEPTH_OF_D_IN_R][(j)]);\
   x[0]  = y[0] - x[1];\

#define keySchedule(s)\
  for (i = 0; i < nw; i++)\
   {\
      ksd[i] = k[(s + i) % (nw + 1)];\
      if (i == nw - 3)\
      {\
         ksd[i] += t[s % 3];\
      }\
      else if (i == nw - 2) \
      {\
         ksd[i] += t[(s + 1) % 3];\
      }\
      else if (i == nw - 1)\
      {\
         ksd[i] += s;\
      }\
   }\


void
init (u64 * key, u64 * tweak)
{
  u32 i;
  u64 knw;

  memset (vd, 0, 128);
  memset (ed, 0, 128);
  memset (fd, 0, 128);
  memset (ksd, 0, 128);

  for (i = 0; i < nw; i++)
    {
      k[i] = key[i];
    }

  knw = EXTENDED_KEY_SCHEDULE_CONST;

  for (i = 0; i < nw; i++)
    {
      knw ^= key[i];
    }

  k[nw] = knw;

  t[0] = tweak[0];
  t[1] = tweak[1];
  t[2] = t[0] ^ t[1];
}

void __stdcall __export
crypt (u64 * p, u64 * c)
{
  u32 i, d, j, s;


  for (i = 0; i < nw; i++)
    {
      vd[i] = p[i];
    }

  for (d = 0; d < nr; d++)
    {

      if (d % SUBKEY_INTERVAL == 0)
        {
          s = d / SUBKEY_INTERVAL;

          keySchedule (s);

          for (i = 0; i < nw; i++)
            {
              ed[i] = vd[i] + ksd[i];
            }
        }
      else
        {
          for (i = 0; i < nw; i++)
            {
              ed[i] = vd[i];
            }
        }

      for (j = 0; j < nw / 2; j++)
        {
          x[0] = ed[j * 2];
          x[1] = ed[j * 2 + 1];

          mix (j, d);

          fd[j * 2] = y[0];
          fd[j * 2 + 1] = y[1];
        }


      for (i = 0; i < nw; i++)
        {
          vd[i] = fd[PI16[i]];
        }
    }

  keySchedule (nr / SUBKEY_INTERVAL);

  for (i = 0; i < nw; i++)
    {
      c[i] = vd[i] + ksd[i];
    }
}

void __stdcall __export
decrypt (u64 * c, u64 * p)
{
  u32 i, d, j, s;


  for (i = 0; i < nw; i++)
    {
      vd[i] = c[i];
    }

  for (d = nr; d > 0; d--)
    {

      if (d % SUBKEY_INTERVAL == 0)
        {
          s = d / SUBKEY_INTERVAL;
          keySchedule (s);

          for (i = 0; i < nw; i++)
            {
              fd[i] = vd[i] - ksd[i];
            }
        }
      else
        {
          for (i = 0; i < nw; i++)
            {
              fd[i] = vd[i];
            }
        }


      for (i = 0; i < nw; i++)
        {
          ed[i] = fd[RPI16[i]];
        }



      for (j = 0; j < nw / 2; j++)
        {
          y[0] = ed[j * 2];
          y[1] = ed[j * 2 + 1];

          demix (j, d - 1);

          vd[j * 2] = x[0];
          vd[j * 2 + 1] = x[1];
        }
    }
