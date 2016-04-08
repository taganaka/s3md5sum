#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "s3md5sum.h"

#define S3MD5_PROG_VERSION "0.0.1"
#define DEFAULT_MULTIPART_CHUNK_SIZE_MB 15

void s3_progress_cb(S3MD5 *s3_md5, size_t idx) {
  char md5string[33];
  int x;
  for (x = 0; x < MD5_DIGEST_LENGTH; x++)
    sprintf(&md5string[x*2], "%02x", s3_md5->digests[idx][x]);

  printf("[*] Chunk #%zu HexDigest %s\n", idx + 1, md5string);
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

void usage(const char* prog){
  fprintf(stderr, "Usage: %s [-cvVh] [-s size] [-e s3_etag] file\n", prog);
  fprintf(stderr, " -c          Check S3/Etag sums of file\n");
  fprintf(stderr, " -s size     Part size in megabyte\n");
  fprintf(stderr, " -e s3_etag  When -c option is given, -e is required\n");
  fprintf(stderr, " -v          Verbose mode\n");
  fprintf(stderr, " -V          Display version information and exit\n");
  fprintf(stderr, " -h          Display this help and exit\n");
}

void version(const char* prog){
  fprintf(stderr, "%s: Calculates and verifies the MD5/S3 Etag of a file uploaded on Amazon S3 using multipart S3 API.\n", prog);
  fprintf(stderr, "Utility version: %s\nAPI version: %s\n",S3MD5_PROG_VERSION, S3MD5_API_VERSION);
}

int main(int argc, char *argv[]) {
  FILE *fp;
  S3MD5 s3;
  S3ETAG s3_etag;
  int fd;
  struct stat st;
  size_t file_size_in_mb;
  size_t min_chunk_size = 0;
  size_t max_chunk_size = 0;
  size_t multipart_chunk_size_mb = 0;
  char *s3_etag_s = NULL;

  int opt;
  enum { CHECK_MODE, GEN_MODE } mode = GEN_MODE;
  bool s3_etag_init = false;
  bool verbose = false;
  FUNC_PTR_CB func_ptr = s3_progress_cb;

  while ((opt = getopt(argc, argv, "cs:e:hvV")) != -1) {
    switch (opt) {
      case 'c': mode = CHECK_MODE; break;
      case 's':
        if (parse_chunk_size(&multipart_chunk_size_mb, optarg) == 0 && multipart_chunk_size_mb > 0){
          if (verbose)
            printf("Setting multipart_chunk_size_mb to %zu\n", multipart_chunk_size_mb);
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
      case 'v':
        verbose = true;
      break;
      case 'h':
        usage(argv[0]);
        return EXIT_SUCCESS;
      break;
      case 'V':
        version(argv[0]);
        return EXIT_SUCCESS;
      break;
      default:
        usage(argv[0]);
        if (s3_etag_s != NULL)
          free(s3_etag_s);
        exit(EXIT_FAILURE);
      }
  }

  // No file given
  if (optind == argc) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (mode == GEN_MODE) {
    if (multipart_chunk_size_mb == 0) {
      multipart_chunk_size_mb = DEFAULT_MULTIPART_CHUNK_SIZE_MB;
    }
    if (s3_etag_init) {
      if (verbose)
        printf("Ignoring -e %s\n", s3_etag_s);
    }
  }

  if (mode == CHECK_MODE && !s3_etag_init) {
    fprintf(stderr, "An -e xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-xx option is required when -c is used\n");
    return EXIT_FAILURE;
  }

  char *file_name = argv[optind];
  fp = fopen(file_name, "rb");
  if (!fp) {
    if (s3_etag_s != NULL)
      free(s3_etag_s);
    perror("fopen");
    return EXIT_FAILURE;
  }

  fd = fileno(fp);
  if (fstat(fd, &st) != 0){
    if (s3_etag_s != NULL)
      free(s3_etag_s);
    perror("fstat");
    return EXIT_FAILURE;
  }

  file_size_in_mb = st.st_size / KB_UNIT / KB_UNIT;

  if (multipart_chunk_size_mb > file_size_in_mb){
    fprintf(stderr, "multipart_chunk_size_mb is greater than current file size.\n");
    fclose(fp);
    if (s3_etag_s != NULL)
      free(s3_etag_s);
    return EXIT_FAILURE;
  }

  if (mode == CHECK_MODE){
    if (verbose)
      printf("Etag info: chunk #: %d MD5 HexDigest: %s\n", s3_etag.part_number, s3_etag.md5_hexdigest);
    if (multipart_chunk_size_mb == 0){

      if (verbose)
        printf("Multipart chunk size not given (-s). Brute force mode on\n");

      min_chunk_size = file_size_in_mb / s3_etag.part_number;
      max_chunk_size = (file_size_in_mb / (s3_etag.part_number - 1));

      if ((max_chunk_size * s3_etag.part_number) > file_size_in_mb \
        && (max_chunk_size * s3_etag.part_number) - file_size_in_mb == max_chunk_size)
        max_chunk_size -= 1;

      if (file_size_in_mb % min_chunk_size != 0)
        min_chunk_size += 1;

      if (verbose)
        printf("Min chunk size: %zu Max chunk size: %zu\n", min_chunk_size, max_chunk_size);

      if ((max_chunk_size - min_chunk_size) > 5) {
        fprintf(stderr, "WARNING: -s options not given.\n\
The etag is located somewhere between %zu and %zu. \
Expect a slow computation if your file is big\n", min_chunk_size, max_chunk_size);
      }

    } else {
      min_chunk_size = max_chunk_size = multipart_chunk_size_mb;
    }
  } else {
    min_chunk_size = max_chunk_size = multipart_chunk_size_mb;
  }

  if (!verbose)
    func_ptr = NULL;

  size_t current_chunk_size;
  bool found = false;
  for (current_chunk_size = min_chunk_size; current_chunk_size <= max_chunk_size; current_chunk_size++){
    if (verbose)
      printf("[*] Set chunk size to %zuMb\n", current_chunk_size);

    S3MD5_Init(&s3, fp, current_chunk_size);
    S3MD5_Compute(&s3, func_ptr);

    if (verbose)
      printf("[*] S3 Etag: %s\n", s3.s3_etag);

    if (mode == CHECK_MODE) {
      if (strcmp(s3.s3_etag, s3_etag_s) == 0) {

        if (verbose)
          printf("\n\
Checksum completed.\n\
File looks valid!\n\
Chunk size: [%zuMb]\n\
Given: [%s]\n\
Computed: [%s]\n\n", current_chunk_size, s3_etag_s, s3.s3_etag);

        S3MD5_Final(&s3);
        found = true;
        printf("%s [%zu]: OK\n", file_name, current_chunk_size);
        break;
      }
    }
    S3MD5_Final(&s3);
    fseek(fp, 0, SEEK_SET);
  }

  if (!found && mode == CHECK_MODE) {
    printf("%s: FAILED\n", file_name);
    fprintf(stderr, "\n\
%s: WARNING computed checksums did NOT match.\n\
File looks corrupted. Try to download it again\n", argv[0]);
  }

  if (mode == GEN_MODE){
    printf("%s [%zu] %s\n", s3.s3_etag, multipart_chunk_size_mb, file_name);
  }

  if (s3_etag_s != NULL)
    free(s3_etag_s);

  fclose(fp);
  return EXIT_SUCCESS;
}
