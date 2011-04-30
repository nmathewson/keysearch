#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <pthread.h>

pthread_mutex_t mutex;
void LOCK(void)
{
  pthread_mutex_lock(&mutex);
}
void UNLOCK(void)
{
  pthread_mutex_unlock(&mutex);
}
#define ASSERT_LOCKED() ((void)0)

/* XXXX use BN_CTX to optimize storage */

/*
  8:
real	0m50.675s
user	1m35.853s
sys	0m0.618s

  25
real	0m45.818s
user	1m27.411s
sys	0m0.447s

  2:
real	0m51.877s
user	1m28.896s
sys	0m1.454s

100:
real	0m40.199s
user	1m17.999s
sys	0m0.354s

*/

int num_cpus = 2;

int primes_per_block = 100;

int max_blocks = (1000/100);

struct block {
  BIGNUM *primes;
};

struct block **blocks = NULL;
int space_for_blocks = 0;
int n_blocks = 0;

static int
grow_blocks(void)
{
  struct block **new_blocks;
  int new_space_for_blocks;

  ASSERT_LOCKED();
  new_space_for_blocks = space_for_blocks;
  if (new_space_for_blocks < 16)
    new_space_for_blocks = 16;
  else
    new_space_for_blocks *= 2;

  new_blocks = realloc(blocks, sizeof(struct block*) * new_space_for_blocks);
  if (new_blocks == NULL) {
    return -1;
  }

  blocks = new_blocks;
  space_for_blocks = new_space_for_blocks;
  return 0;
}

static int
add_block(struct block *blk)
{
  LOCK();
  if (space_for_blocks <= n_blocks) {
    if (grow_blocks() < 0) {
      UNLOCK();
      return -1;
    }
  }

  blocks[n_blocks++] = blk;
  UNLOCK();
  return 0;
}

#define PRIME_BITS 512
static BIGNUM *exp;

static int
set_exponent(unsigned val)
{
  if (!(exp = BN_new()))
    return -1;
  if (BN_set_word(exp, val)<0)
    return -1;
  return 0;
}

static int
digest_good(const unsigned char digest[])
{
  return 0;
}


static int
declare_match(BIGNUM *p, BIGNUM *q)
{
  /* looks like a match; announce it! XXXX */
  return 0;
}

static int
check_key(BIGNUM *p, BIGNUM *q, BN_CTX *ctx)
{
  BIGNUM *tmp = BN_new();/*XXXX use ctx */
  RSA rsa;
  unsigned char key_out[1024];
  unsigned char d[20];
  unsigned char *cp;
  int len, res = 0;

  memset(&rsa, 0, sizeof(rsa));
  BN_mul(tmp, p, q, ctx);
  /* This is not how you build an RSA! XXXX */
  rsa.e = exp;
  rsa.n = tmp;

  cp = key_out;
  len = i2d_RSAPublicKey(&rsa, &cp);
  assert(len > 0);
  SHA1(key_out, len, d);

  if (digest_good(d)) {
    declare_match(p, q);
    res = 1;
  }

  BN_free(tmp);
  return res;
}

static int
check_blocks(struct block *a, struct block *b)
{
  const int N = primes_per_block;
  int i, j;
  BN_CTX *ctx = BN_CTX_new();

  if (!ctx)
    return -1;

  if (a == b) {
    for (i=1; i < N; ++i) {
      for (j=0; j < i; ++j) {
        check_key(&a->primes[i], &a->primes[j], ctx);
      }
    }
  } else {
    for (i=0; i < N; ++i) {
      for (j=0; j < N; ++j) {
        check_key(&a->primes[i], &b->primes[j], ctx);
      }
    }
  }

  BN_CTX_free(ctx);
  return 0;
}

static struct block *
new_block(void)
{
  int i;
  struct block *blk;
  BIGNUM *p_minus_1, *gcd;
  BIGNUM *p = NULL;

  BN_CTX *ctx = BN_CTX_new(); /* free more carefully on error XXXX */

  if (!(blk = malloc(sizeof(struct block))))
    return NULL;

  if (!(blk->primes = malloc(sizeof(BIGNUM)*primes_per_block))) {
    free(blk);
    return NULL;
  }

  for (i = 0; i < primes_per_block; ++i) {
    BN_init(&blk->primes[i]);
  }

  if (!(p_minus_1 = BN_CTX_get(ctx)))
    goto err;
  if (!(gcd = BN_CTX_get(ctx)))
    goto err;

  for (i = 0; i < primes_per_block; ++i) {
    while (1) {
      p = &blk->primes[i];
      p = BN_generate_prime(p, PRIME_BITS, 0,
                        NULL, NULL, NULL, NULL);
      if (p == NULL)
        goto err;
      if (p != &blk->primes[i])
        goto err;
      if (!BN_sub(p_minus_1,p,BN_value_one()))
        goto err;
      if (!BN_gcd(gcd,p_minus_1,exp,ctx))
        goto err;
      if (BN_is_one(gcd)) /* p is relatively prime to exp: good! */
        break;
    }
  }

  BN_CTX_free(ctx);

  return blk;

 err:
  puts("ERROR generating block");
  /* XXX free everything */
  return NULL;
}

struct job {
  int all_done;
  int generate;
  struct block *block1;
  struct block *block2;
};

static int next_block1=0, next_block2=0;

int
get_next_job(struct job *job_out, int thr)
{
  int res = -1;
  memset(job_out, 0, sizeof(struct job));

  LOCK();
  if (n_blocks < num_cpus || next_block2 >= n_blocks) {
    if (n_blocks >= max_blocks) {
      printf("%d Done",thr);
      job_out->all_done = 1;
      res = 0;
      goto done;
    }
    printf("%d Generate block %d\n", thr, n_blocks);
    job_out->generate = 1;
    res = 0;
    goto done;
  }
  printf("%d Try block %d vs %d\n", thr, next_block1, next_block2);
  job_out->block1 = blocks[next_block1];
  job_out->block2 = blocks[next_block2];

  if (++next_block1 > next_block2) {
    next_block1 = 0;
    ++next_block2;
  }

  res = 0;
 done:
  UNLOCK();
  return res;
}

void *
worker(void *arg)
{
  struct job job;
  while (1) {

    if (get_next_job(&job, (int)arg) < 0)
      return (void*)-1;
    if (job.all_done)
      return (void*)0;

    if (job.generate) {
      struct block *blk = new_block();
      if (!blk)
        return (void*)-1;
      add_block(blk);
    } else {
      check_blocks(job.block1, job.block2);
    }
  }

  return (void*)0;
}

int main(int c, char **v)
{
  /* XXXX init RNG */
  /* XXXX init openssl locks? */

  pthread_t *threads;
  int i;

  pthread_mutex_init(&mutex, NULL);
  if (set_exponent(65537) < 0) {
    puts("Aargh.");
    return 1;
  }

  if (!(threads = calloc(num_cpus, sizeof(pthread_t)))) {
    perror("calloc");
    return 1;
  }

  for (i = 0; i < num_cpus; ++i) {
    if (pthread_create(&threads[i], NULL, worker, (void*)i)) {
      perror("pthread_create");
      return 1;
    }
  }

  for (i = 0; i < num_cpus; ++i) {
    void *res;
    if (pthread_join(threads[i], &res)) {
      perror("pthread_join");
      return 1;
    }
  }

  return 0;
}
