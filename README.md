# hashID | hash-identifier

Identify the different types of hashes used to encrypt data and especially passwords.  
hashID is a rewrite of the old [hashID](https://github.com/psypanda/hashID) in Go which supports the identification of over 430 unique hash types using regular expressions.  
It is able to identify a single hash or parse a file and identify the hashes within them.  
hashID is also capable of including the corresponding [hashcat](https://hashcat.net/hashcat/) mode and/or [JohnTheRipper](https://www.openwall.com/john/) format in its output.  
> **Note:** When identifying a hash on *nix operating systems use single quotes to prevent interpolation.

## Usage

```console
USAGE:
   hashID [global options] [command [command options]] [arguments...]

COMMANDS:
   hash, id  Identify hash from input string
   file, fn  Identify hashes from input file
   list, ls  Shows information about supported hash types
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --exotic, -x                        include exotic hash types (default: false)
   --extended, -e                      include extended hash types (default: false)
   --output [json|xml], -o [json|xml]  set output format [json|xml] (default: console)
   --help, -h                          show help (default: false)
   --version, -v                       print the version (default: false)
```

### Example

```console
$ hashID id '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
Analyzing '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
[+] PHPass' Portable Hash
[+] PHPass, WordPress (MD5), Joomla (MD5)

$ hashID id -mj '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
Analyzing: '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
[+] RACF [Hashcat: 8500][John: racf]

$ hashID -o=json id -mj '$2a$12$djEXehnXL2xWQRq5w.LbFOaNDNlebYzDbAfwWwzY7oKrbdMe4OYwO'
{"hash":"$2a$12$djEXehnXL2xWQRq5w.LbFOaNDNlebYzDbAfwWwzY7oKrbdMe4OYwO","match":[{"name":"bcrypt","john":"bcrypt"},{"name":"bcrypt $2*$, Blowfish (Unix)","hashcat":"3200","john":"bcrypt"},{"name":"WBB4 (Woltlab Burning Board)"}]}

$ hashID file hashes.txt
Analyzing: "*85ADE5DDF71E348162894C71D73324C043838751"
[+] MySQL4.1/MySQL5 

Analyzing: "8743b52063cd84097a65d1633f5c74f5"
[+] DNSSEC (NSEC3) 
[+] Domain Cached Credentials (DCC), MS Cache 
[+] Domain Cached Credentials 2 (DCC2), MS Cache 2 
[+] MD5 
[+] NTLM 
[+] PostgreSQL

$ hashID -o=json file split --modes hashes.txt
{"hash":"*85ADE5DDF71E348162894C71D73324C043838751","match":[{"name":"MySQL4.1/MySQL5"}]}
{"hash":"8743b52063cd84097a65d1633f5c74f5","match":[{"name":"DNSSEC (NSEC3)"},{"name":"Domain Cached Credentials (DCC), MS Cache"},{"name":"Domain Cached Credentials 2 (DCC2), MS Cache 2"},{"name":"MD5"},{"name":"NTLM"},{"name":"PostgreSQL"}]}
```

## Disclaimer

hashID started in 2013 as a learning project for regular expressions and Python. Since then, other hash identifiers like [Name-That-Hash](https://github.com/HashPals/Name-That-Hash) and [Haiti](https://github.com/noraj/haiti) have appeared, expanding and updating the database of regular expressions and offering additional features. If you require more than a simple CLI tool, consider these alternatives. This version, rewritten in Go, offers similar functionality to the original, with an updated database of hashes and regular expressions.

## Resources

- [https://passlib.readthedocs.io/en/stable/index.html](https://passlib.readthedocs.io/en/stable/index.html)
- [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)
- [https://github.com/openwall/john/tree/bleeding-jumbo/src](https://github.com/openwall/john/tree/bleeding-jumbo/src)
- [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [https://github.com/hashcat/hashcat/tree/master/src/modules](https://github.com/hashcat/hashcat/tree/master/src/modules)
