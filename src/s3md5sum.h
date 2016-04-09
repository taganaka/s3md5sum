#ifndef S3MD5SUM_H_
#define S3MD5SUM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/md5.h>
#endif

#define S3MD5_API_VERSION "0.0.1"
#define KB_UNIT 1024

typedef unsigned char byte;

typedef struct __S3MD5 {
  size_t size;
  size_t part_size;
  size_t part_number;
  size_t current_chunk;
  size_t processed;
  FILE *fp;
  byte **digests;
  byte *final_digest;
  byte *temp_buffer;
  char *s3_etag;
  MD5_CTX md5c;
} S3MD5;

typedef struct __S3ETAG {
  int part_number;
  char md5_hexdigest[33];
} S3ETAG;

typedef void (*FUNC_PTR_CB)(S3MD5 *s3_md5, size_t current_chunk);
int S3MD5_ParseEtag(S3ETAG *etag, const char *etag_s);
int S3MD5_Init(S3MD5 *s3_md5, FILE *fp, const size_t chunk_size);
void S3MD5_Final(S3MD5 *s3_md5);
void S3MD5_Compute(S3MD5 *s3_md5, FUNC_PTR_CB func);

int __S3MD5_Update(S3MD5 *s3_md5);

int S3MD5_ParseEtag(S3ETAG *etag, const char *etag_s) {
  int len;
  len = strlen(etag_s);
  if (len < 34){
    fprintf(stderr, "S3MD5_ParseEtag: %s doesn't look like a valid S3 multipart etag (len)\n", etag_s);
    return -1;
  }

  if (sscanf(etag_s, "%32[a-f0-9]-%d", etag->md5_hexdigest, &etag->part_number) != 2){
    fprintf(stderr, "S3MD5_ParseEtag: %s doesn't look like a valid S3 multipart etag (sscanf)\n", etag_s);
    return -1;
  }

  if (strlen(etag->md5_hexdigest) != 32){
    fprintf(stderr, "S3MD5_ParseEtag: %s doesn't look like a valid S3 multipart etag (len != 32)\n", etag_s);
    return -1;
  }

  return 0;
}

int S3MD5_Init(S3MD5 *s3_md5, FILE *fp, const size_t chunk_size) {
  int fd;
  struct stat st;
  size_t size_in_mb;

  fd = fileno(fp);
  if (fstat(fd, &st) != 0){
    perror("fstat");
    return -1;
  }

  s3_md5->fp = fp;
  s3_md5->current_chunk = 0;
  s3_md5->processed = 0;
  s3_md5->size = st.st_size;
  MD5_Init(&s3_md5->md5c);

  size_in_mb = s3_md5->size / KB_UNIT / KB_UNIT;
  s3_md5->part_size = chunk_size;
  s3_md5->part_number  = size_in_mb / chunk_size;
  if (size_in_mb % s3_md5->part_size != 0)
    s3_md5->part_number++;

  int n_of_digits = snprintf(0, 0, "%zu", s3_md5->part_number);
  s3_md5->s3_etag = malloc(34 + n_of_digits);
  if (s3_md5->s3_etag == NULL){
    perror("malloc");
    return -1;
  }

  size_t i;
  s3_md5->digests = (byte**)malloc(s3_md5->part_number * sizeof(char*));
  for (i = 0; i < s3_md5->part_number; i++) {
    s3_md5->digests[i] = (byte*)malloc(MD5_DIGEST_LENGTH);
    if (s3_md5->digests[i] == NULL){
      perror("malloc");
      return -1;
    }
  }

  s3_md5->final_digest = (byte*)malloc(MD5_DIGEST_LENGTH);
  if (s3_md5->final_digest == NULL){
    perror("malloc");
    return -1;
  }

  s3_md5->temp_buffer = (byte*)malloc(15 * KB_UNIT * KB_UNIT);
  if (s3_md5->temp_buffer == NULL){
    perror("malloc");
    return -1;
  }

  return 0;
}

void S3MD5_Final(S3MD5 *s3_md5){
  if (s3_md5 != NULL){
    for (size_t i = 0; i < s3_md5->part_number; i++) {
      free(s3_md5->digests[i]);
    }
    free(s3_md5->digests);
    free(s3_md5->final_digest);
    free(s3_md5->s3_etag);
    free(s3_md5->temp_buffer);
  }
}

void S3MD5_Compute(S3MD5 *s3_md5, FUNC_PTR_CB func_ptr) {
  size_t idx = 0;
  while ((idx = __S3MD5_Update(s3_md5)) != -1) {
    if (func_ptr != NULL) {
      func_ptr(s3_md5, idx);
    }
  }
  int x;
  for (x = 0; x < MD5_DIGEST_LENGTH; x++)
    sprintf(&s3_md5->s3_etag[x*2], "%02x", s3_md5->final_digest[x]);
  s3_md5->s3_etag[32] = '-';
  sprintf((s3_md5->s3_etag + 33), "%zu", s3_md5->part_number);
}

int __S3MD5_Update(S3MD5 *s3_md5){
  int buff_size = 64 * KB_UNIT;
  size_t part_size_in_bytes = s3_md5->part_size * KB_UNIT * KB_UNIT;
  size_t to_read = 0;
  size_t current = 0;
  size_t readed = 0;

  if (s3_md5->current_chunk == s3_md5->part_number){
    if (s3_md5->processed != s3_md5->size){
      S3MD5_Final(s3_md5);
      abort();
    }
    MD5_Final(s3_md5->final_digest, &s3_md5->md5c);
    return -1;
  }

  MD5_CTX context;
  MD5_Init(&context);

  while (readed < part_size_in_bytes) {
    if (readed + buff_size <= part_size_in_bytes)
      to_read = buff_size;
    else
      to_read = part_size_in_bytes - readed;

    current = fread(s3_md5->temp_buffer, 1, to_read, s3_md5->fp);

    if (current <= 0)
      break;
    readed += current;
    MD5_Update(&context, s3_md5->temp_buffer, current);
  }

  MD5_Final(s3_md5->digests[s3_md5->current_chunk], &context);
  MD5_Update(&s3_md5->md5c, s3_md5->digests[s3_md5->current_chunk], MD5_DIGEST_LENGTH);

  s3_md5->processed += readed;
  return s3_md5->current_chunk++;
}

#endif /* S3MD5SUM_H_ */
