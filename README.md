# hashID | hash-identifier

Identify the different types of hashes used to encrypt data and especially passwords.  
hashID is a rewrite of the old [hashID](https://github.com/psypanda/hashID) in Go which supports the identification of over 430 unique hash types using regular expressions.  
It is able to identify a single hash or parse a file and identify the hashes within them.  
hashID is also capable of including the corresponding [hashcat](https://hashcat.net/hashcat/) mode and/or [JohnTheRipper](https://www.openwall.com/john/) format in its output.  
> **Note:** When identifying a hash on *nix operating systems use single quotes to prevent interpolation.

## Usage

```shell
hashID [global options] command [command options] [arguments...]
```

### Example

```console
$ hashID '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
Analyzing '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
[+] PHPass' Portable Hash
[+] phpass, WordPress (MD5), Joomla (MD5)

$ hashID -mj '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
Analyzing: '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
[+] RACF [Hashcat: 8500][John: racf]

$ hashID -mj -o json '$2a$12$djEXehnXL2xWQRq5w.LbFOaNDNlebYzDbAfwWwzY7oKrbdMe4OYwO'
{"hash":"$2a$12$djEXehnXL2xWQRq5w.LbFOaNDNlebYzDbAfwWwzY7oKrbdMe4OYwO","match":[{"name":"bcrypt"},{"name":"bcrypt $2*$, Blowfish (Unix)","hashcat":"3200","john":"bcrypt"},{"name":"WBB4 (Woltlab Burning Board)"}]}

$ hashID file hashes.txt
Analyzing: '*85ADE5DDF71E348162894C71D73324C043838751'
[+] MySQL4.1/MySQL5 

Analyzing: '8743b52063cd84097a65d1633f5c74f5'
[+] DNSSEC (NSEC3) 
[+] Domain Cached Credentials (DCC), MS Cache 
[+] Domain Cached Credentials 2 (DCC2), MS Cache 2 
[+] MD5 
[+] NTLM 
[+] PostgreSQL
```

## Disclaimer

hashID started in 2013 as a learning project for regular expressions and Python. Since then, other hash identifiers like [Name-That-Hash](https://github.com/HashPals/Name-That-Hash) and [Haiti](https://github.com/noraj/haiti) have appeared, expanding and updating the database of regular expressions. If you require more than a simple CLI tool, consider these alternatives. This version, rewritten in Go, offers similar functionality to the original, with an updated database of hashes and regular expressions.

## Resources

- [https://passlib.readthedocs.io/en/stable/index.html](https://passlib.readthedocs.io/en/stable/index.html)
- [http://openwall.info/wiki/john](http://openwall.info/wiki/john)
- [http://openwall.info/wiki/john/sample-hashes](http://openwall.info/wiki/john/sample-hashes)
- [http://hashcat.net/wiki/doku.php?id=example_hashes](http://hashcat.net/wiki/doku.php?id=example_hashes)
