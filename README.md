# hashID | hash-identifier

Identify the different types of hashes used to encrypt data and especially passwords.  
hashID is a tool written in Go which supports the identification of over 220 unique hash types using regular expressions.  
It is able to identify a single hash or parse a file and identify the hashes within them.  
hashID is also capable of including the corresponding [hashcat](https://hashcat.net/hashcat/) mode and/or [JohnTheRipper](https://www.openwall.com/john/) format in its output.  
**Note:** *When identifying a hash on *nix operating systems use single quotes to prevent interpolation.*

## Install

TODO

## Usage

TODO

## Example

```cmd
$ hashid '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
Analyzing '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
[+] Wordpress ≥ v2.6.2
[+] Joomla ≥ v2.5.18
[+] PHPass' Portable Hash

$ hashid -mj '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
Analyzing '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
[+] RACF [Hashcat Mode: 8500][JtR Format: racf]

$ hashid file hashes.txt
--File 'hashes.txt'--
Analyzing '*85ADE5DDF71E348162894C71D73324C043838751'
[+] MySQL5.x
[+] MySQL4.1
Analyzing '$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
--End of file 'hashes.txt'--
```

### Resources

- [http://pythonhosted.org/passlib/index.html](http://pythonhosted.org/passlib/index.html)
- [http://openwall.info/wiki/john](http://openwall.info/wiki/john)
- [http://openwall.info/wiki/john/sample-hashes](http://openwall.info/wiki/john/sample-hashes)
- [http://hashcat.net/wiki/doku.php?id=example_hashes](http://hashcat.net/wiki/doku.php?id=example_hashes)
