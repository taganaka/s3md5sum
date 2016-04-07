#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "s3md5sum.h"

#define DEFAULT_MULTIPART_CHUNK_SIZE_MB 12

void s3_progress_cb(S3MD5 *s3_md5, size_t idx) {
  char md5string[33];
  int x;
  for (x = 0; x < MD5_DIGEST_LENGTH; x++)
    sprintf(&md5string[x*2], "%02x", s3_md5->digests[idx][x]);

  printf("[*] Chuck #%zu HexDigest %s\n", idx + 1, md5string);
}

int parse_chunk_size(size_t *dest, char *val){
  char *end = val;
  errno = 0;
  *dest = strtoll(val, &end, 10);
  if (errno == ERANGE || *dest > INT_MAX) {
    return -1;
  } else if (*end) {
    return -1;
  }
  return -0;
}

int main(int argc, char *argv[]) {
  FILE *fp;
  S3MD5 s3;
  S3ETAG s3_etag;
  int fd;
  struct stat st;
  size_t size_in_mb;
  size_t min_chunk_size = 0;
  size_t max_chunk_size = 0;
  size_t multipart_chunk_size_mb = 0;
  char *s3_etag_s;

  int opt;
  int argv_index;
  enum { CHECK_MODE, GEN_MODE } mode = GEN_MODE;
  bool s3_etag_init = false;
  bool verbose = false;
  FUNC_PTR_CB func_ptr = s3_progress_cb;

  while ((opt = getopt(argc, argv, "cs:e:hV")) != -1) {
    switch (opt) {
      case 'c': mode = CHECK_MODE; break;
      case 's':
        if (parse_chunk_size(&multipart_chunk_size_mb, optarg) == 0 && multipart_chunk_size_mb > 0){
          printf("Setting parsed_chunck_size to %zu\n", multipart_chunk_size_mb);
        } else {
          fprintf(stderr, "-s %s not a valid number\n", optarg);
          return EXIT_FAILURE;
        }
      break;
      case 'e':
        if (S3MD5_ParseEtag(&s3_etag, optarg) == 0) {
          s3_etag_init = true;
          s3_etag_s = (char *)malloc(strlen(optarg) + 1);
          strcpy(s3_etag_s, optarg);
        } else {
          return EXIT_FAILURE;
        }
      break;
      case 'V':
        verbose = true;
      break;
      default:
        fprintf(stderr, "Usage: %s [-cshV] [file...]\n", argv[0]);
        exit(EXIT_FAILURE);
      }
  }

  if (mode == GEN_MODE) {
    if (multipart_chunk_size_mb == 0) {
      multipart_chunk_size_mb = DEFAULT_MULTIPART_CHUNK_SIZE_MB;
    }
  }

  if (mode == CHECK_MODE && !s3_etag_init) {
    fprintf(stderr, "An -e xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-xx option is required when -c is used\n");
    return EXIT_FAILURE;
  }

  argv_index = optind;
  char *file_name = argv[argv_index];
  fp = fopen(file_name, "rb");
  if (!fp) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  fd = fileno(fp);
  if (fstat(fd, &st) != 0){
    perror("fstat");
    return EXIT_FAILURE;
  }

  if (mode == CHECK_MODE){
    if (verbose)
      printf("Etag info: chunck #: %d MD5 HexDigest: %s\n", s3_etag.part_number, s3_etag.md5_hexdigest);
    if (multipart_chunk_size_mb == 0){
      if (verbose)
        printf("Multipart chunck size not given (-s). Brute force mode on\n");
      size_in_mb = st.st_size / BYTES_UNIT / BYTES_UNIT;
      min_chunk_size = size_in_mb / s3_etag.part_number;
      max_chunk_size = (size_in_mb / (s3_etag.part_number - 1));

      if ((max_chunk_size * s3_etag.part_number) > size_in_mb \
        && (max_chunk_size * s3_etag.part_number) - size_in_mb == max_chunk_size)
        max_chunk_size -= 1;

      if (size_in_mb % min_chunk_size != 0)
        min_chunk_size += 1;

      if (verbose)
        printf("Min chunck size: %zu Max chunck size: %zu\n", min_chunk_size, max_chunk_size);
    } else {
      min_chunk_size = max_chunk_size = multipart_chunk_size_mb;
    }
  }

  if (!verbose)
    func_ptr = NULL;

  size_t current_chunck_size;
  bool found = false;
  for (current_chunck_size = min_chunk_size; current_chunck_size <= max_chunk_size; current_chunck_size++){
    if (verbose)
      printf("[*] Try with %zuMb as chunck size\n", current_chunck_size);

    S3MD5_Init(&s3, fp, current_chunck_size);
    S3MD5_Compute(&s3, func_ptr);

    if (verbose)
      printf("[*] S3 Etag: %s\n", s3.s3_etag);

    if (mode == CHECK_MODE) {
      if (strcmp(s3.s3_etag, s3_etag_s) == 0) {

        if (verbose)
          printf("\n\
Checksum completed.\n\
File looks valid!\n\
Chunck size: [%zuMb]\n\
Given: [%s]\n\
Computed: [%s]\n\n", current_chunck_size, s3_etag_s, s3.s3_etag);

        S3MD5_Final(&s3);
        found = true;
        printf("%s: OK\n", file_name);
        break;
      }
    }
    S3MD5_Final(&s3);
    fseek(fp, 0, SEEK_SET);
  }
  fclose(fp);

  if (!found) {
    printf("%s: FAILED\n", file_name);
    fprintf(stderr, "\n\
%s: WARNING computed checksums did NOT match.\n\
File looks corrupted. Try to download it again", argv[0]);
  }

  if (s3_etag_s != NULL)
    free(s3_etag_s);

  return EXIT_SUCCESS;
}
