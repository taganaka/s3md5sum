all:
	gcc -Wall -O2 -Isrc/ src/s3md5sum.c -o s3md5sum -std=gnu99 -lssl -lcrypto

clean:
	rm -f s3md5sum s3md5sum-debug

debug:
	gcc -Wall -O0 -g -Isrc/ src/s3md5sum.c -o s3md5sum-debug -std=gnu99 -lssl -lcrypto
