#include <stdio.h>
#include <stdlib.h>
#include "s3md5sum.h"

void s3_progress_cb(S3MD5 *s3_md5, size_t idx) {
  char md5string[33];
  int x;
  for (x = 0; x < MD5_DIGEST_LENGTH; x++)
    sprintf(&md5string[x*2], "%02x", s3_md5->digests[idx][x]);

  printf("Chuck #%zu HexDigest %s\n", idx, md5string);
}

int main(int argc, char const *argv[]) {
  FILE *fp;
  S3MD5 s3;
  S3ETAG s3_etag;
  int fd;
  struct stat st;
  size_t size_in_mb, min_chunk_size, max_chunk_size;

  if (S3MD5_ParseEtag(&s3_etag, argv[2]) == 0) {
    printf("Chunck #: %d MD5 HexDigest: %s\n", s3_etag.part_number, s3_etag.md5_hexdigest);
  }

  fp = fopen(argv[1], "rb");
  if (!fp) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  fd = fileno(fp);
  if (fstat(fd, &st) != 0){
    perror("fstat");
    return -1;
  }

  size_in_mb = st.st_size / BYTES_UNIT / BYTES_UNIT;
  min_chunk_size = size_in_mb / s3_etag.part_number;
  max_chunk_size = (size_in_mb / (s3_etag.part_number - 1));

  if ((max_chunk_size * s3_etag.part_number) > size_in_mb \
    && (max_chunk_size * s3_etag.part_number) - size_in_mb == max_chunk_size) {
    max_chunk_size -= 1;
  }

  if (size_in_mb % min_chunk_size != 0) {
    min_chunk_size += 1;
  }

  printf("Min chunck size: %zu Max chunck size: %zu\n", min_chunk_size, max_chunk_size);

  size_t current_chunck_size;
  bool found = false;
  for (current_chunck_size = min_chunk_size; current_chunck_size <= max_chunk_size; current_chunck_size++){
    printf("[*] Try with %zu as chunck size\n", current_chunck_size);
    S3MD5_Init(&s3, fp, current_chunck_size);
    S3MD5_Compute(&s3, s3_progress_cb);
    printf("S3 Etag: %s\n", s3.s3_etag);
    if (strcmp(s3.s3_etag, argv[2]) == 0) {
      printf("\n \
Checksum completed!\n \
File looks valid!\n \
Chunck size: [%zuMb]\n \
Given: [%s]\n \
Computed: [%s]\n", current_chunck_size, argv[2], s3.s3_etag);
      S3MD5_Final(&s3);
      found = true;
      break;
    }

    S3MD5_Final(&s3);
    fseek(fp, 0, SEEK_SET);
  }
  fclose(fp);

  if (!found) {
    printf("\n \
MD5 mismatch.\n \
File looks corrupted. Try to download it again\n");
  }
  return EXIT_SUCCESS;
}
