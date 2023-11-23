# hashID | hash-identifier

Identify the different types of hashes used to encrypt data and especially passwords.  
hashID is a tool written in Go which supports the identification of over 220 unique hash types using regular expressions.  
It is able to identify a single hash or parse a file and identify the hashes within them.  
hashID is also capable of including the corresponding [hashcat](https://hashcat.net/hashcat/) mode and/or [JohnTheRipper](https://www.openwall.com/john/) format in its output.  
**Note:** When identifying a hash on *nix operating systems use single quotes to prevent interpolation.

## Install

TODO

## Usage

TODO

## Example

```cmd
$ hashid '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
Analyzing '$P$8ohUJ.1sdFw09/bMaAQPTGDNi2BIUt1'
[+] PHPass' Portable Hash
[+] phpass, WordPress (MD5), Joomla (MD5)

$ hashid -mj '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
Analyzing '$racf$*AAAAAAAA*3c44ee7f409c9a9b'
[+] RACF [Hashcat Mode: 8500][JtR Format: racf]

$ hashid file hashes.txt
--File 'hashes.txt'--
Analyzing '*85ADE5DDF71E348162894C71D73324C043838751'
[+] MySQL4.1/MySQL5
Analyzing '$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq'
[+] WBB4 (Woltlab Burning Board)
[+] bcrypt
[+] bcrypt $2*$, Blowfish (Unix)
[+] bcrypt(md5($pass)) / bcryptmd5
[+] bcrypt(sha1($pass)) / bcryptsha1
--End of file 'hashes.txt'--
```

### Resources

- [http://pythonhosted.org/passlib/index.html](http://pythonhosted.org/passlib/index.html)
- [http://openwall.info/wiki/john](http://openwall.info/wiki/john)
- [http://openwall.info/wiki/john/sample-hashes](http://openwall.info/wiki/john/sample-hashes)
- [http://hashcat.net/wiki/doku.php?id=example_hashes](http://hashcat.net/wiki/doku.php?id=example_hashes)
