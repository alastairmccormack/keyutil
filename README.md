keyutil
=======

*- A sensible Java key management tool for normal people*

Merges mutil-part PEM files (Concatenated PEM certs) and Java Keystores into new or existing Java Keystore JKS files

# Example Usage
## PEM and JKS Import

```
java -jar keyutil.jar --new-keystore trustStore.jks --password <secret> \
--import-pem-file /etc/pki/tls/certs/ca-bundle.trust.crt /opt/myapp/mycerts.pem --import-jks-file /opt/myotherapp/trustStore.jks:mysecret
```

# Download

https://github.com/use-sparingly/keyutil/releases/download/0.4.0/keyutil-0.4.0.jar

## Help

```
java -jar keyutil.jar --help

usage: keyutil [-d | -q] [-e <PEM_file [<PEM_files>..]>] [-f <jks_file> | -n <jks_file>] [-F] -h | -i | -l  [-j
       <JKS_file:password [<JKS_file:password>..]>]   -p <arg>
 -d,--debug                                                         Debug
 -e,--import-pem-file <PEM_file [<PEM_files>..]>                    PEM import filenames
 -f,--keystore-file <jks_file>                                      Append to existing output JKS keystore filename
 -F,--force-new-overwrite                                           force overwrite of existing keystore
 -h,--help                                                          Show help
 -i,--import                                                        Import certs mode
 -j,--import-jks-file <JKS_file:password [<JKS_file:password>..]>   JKS import filename using given password
 -l,--list                                                          List cert mode
 -n,--new-keystore <jks_file>                                       Append to new output JSK keystore filename
 -p,--password <arg>                                                Keystore (secret) password
 -q,--quiet                                                         Quiet
 
```

# Why?
Redhat uses a multi-part PEM file (/etc/pki/tls/certs/ca-bundle.crt). Keyutil can be used to keep Java's cacert file in sync with the Redhat's ca-bundle.crt.

Ubuntu uses a directory containing single PEM files. Keyutil can merge all of these into a single JKS file, such as a cacerts files.

You could also use it to combine a number of system cert files and custom cert files together.

## What's wrong with keytool?
* Unable to import PEM files with headers (No more: "keytool error: java.lang.Exception: Input not an X.509 certificate")
* Unable to import multi-part PEM files
* Unable to import multiple files in one iteration
* Annoying argument syntax
