# s3md5sum #

s3md5sum calculates and verifies the MD5/S3 Etag of a file uploaded on Amazon S3 using multipart S3 API.

Each file which is larger than 5GB its uploaded on S3 in smaller chunks of an arbitrary size.  
When the whole file is uploaded, S3 assigns an Etag containing the signature of the file.  
Etag is in the form of `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-dd`. The first part is the hexadecimal representation of an MD5 hash while the second part is always a number indicating the number of parts used to upload the file

Es:

`3d15a57fe725ad2cd061526b77b0b86a-2`

The MD5 is calculated using the following algorithm:

Calculate the MD5 hash for each uploaded part of the file, concatenate the hashes into a single binary string and calculate the MD5 hash of that result.

### Guessing the size of each part

In order to verify a downloaded file, the size used to upload each part has to be known.  
Unfortunately (AFAIK) this information is not exposed back from S3 so unless you know what was the size used during a multipart upload, brute-forcing the size is the only available option.  
Luckily, given a valid Etag as input and knowing the size of the local file, it's possible to guess somehow where the original used size would be.

### Obtaining S3/Etag

S3/Etag can be obtained by inspecting the HTTP headers received when a file is downloaded, visiting the S3 web console or using a cli tool such as s3cmd

Es:

```
$ s3cmd info s3://foo-bar/file.tgz
s3://foo-bar/file.tgz (object):
   File size: 2632516333
   Last mod:  Fri, 18 Jul 2014 16:59:13 GMT
   MIME type: binary/octet-stream
   Storage:   STANDARD
   MD5 sum:   6ada2547ed471525c3e6a7b76f379940-168
   SSE:       none
   policy:    none
   cors:      none
   ACL:       user: FULL_CONTROL
```

### Usage

```
s3md5sum [-cvVh] [-s size] [-e s3_etag] file
 -c          Check S3/Etag sums of file
 -s size     Part size in megabyte
 -e s3_etag  When -c option is given, -e is required
 -v          Verbose mode
 -V          Display version information and exit
 -h          Display this help and exit
```

### Compile & Run

On Ubuntu/Debian:

```
$ apt-get install build-essential libssl-dev
$ make
$ ./s3md5sum
```

### Author

Francesco Laurita <francesco.laurita@gmail.com>
