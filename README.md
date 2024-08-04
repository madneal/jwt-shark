# jwt-shark

A JWT crack tool developped in Rust. Supports dictionary attacks with a token file.

Help

```shell
./jwt-shark --help                                                                                      
Usage: jwt-shark [OPTIONS] -t <token_file>

Options:
  -c <concurrency>      Set concurrent workers [default: 10]
  -t <token_file>       File containing JWT token(s)
  -d <dict_file>        Dictionary file. If omitted, will read from stdin
  -h, --help            Print help
```
