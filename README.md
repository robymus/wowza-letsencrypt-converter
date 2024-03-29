# wowza-letsencrypt-converter

Simple utility to convert all let's encrypt certificates to JKS store and create a domain to keystore map for Wowza Streaming Engine (4.5.0+).

Wowza Streaming Engine can reload domain mapped keystores when the keystore map file changes, so running this converter utility after certificate renewals (or after adding or removing certificates) will let a running server reinitialize its certificate store with the updated certificates.
 
## Compile

```Shell
gradle jar
```

Or download a precompiled jar from [Releases](https://github.com/robymus/wowza-letsencrypt-converter/releases).

## Usage

```Shell
java -jar wowza-letsencrypt-converter-0.2.jar [-v] <output-path> [<letsencrypt-live-path>] [<password>]
```

The  *letsencrypt-live-path* parameter defaults to /etc/letsencrypt/live, as is in common Linux systems, might be different on others. The *output-path* must be an existing and writable directory, here a new JKS keystore will be created for every certificate in the input directory together with a file jksmap.txt containing the domain to keystore mapping to be used in the VHost.xml of Wowza Streaming Engine.

The generated JKS default password will be 'secret'.

Feel free to fork if you need additional functionality.

## Usage with acme.sh

Since 0.2 the tool supports PKCS#1 private key format (this is the format generated by acme.sh). To use it with acme.sh generated certificates, create a base directory and create a subdirectory with the name of each domain you want to generate the jksmap for, then use the [install-cert](https://github.com/Neilpang/acme.sh#3-install-the-cert-to-apachenginx-etc) option to export the full chain and private key files as `fullchain.pem` and `privkey.pem` into the domain's directory.

```Shell
mkdir /opt/acme-pems
mkdir /opt/acme-pems/example.com
acme.sh --install-cert -d example.com \
        --key-file /opt/acme-pems/example.com/privkey.pem \
        --fullchain-file /opt/acme-pems/example.com/fullchain.pem
```

Then run the converter with the base directory as the letsencrypt-live-path parameter (or simply use /etc/letsencrypt/live as this base directory)

## Real life

Tested on Amazon Linux with Wowza Streaming Engine 4.6.0.

## License

Licensed under the MIT license. 
 
## Requirements

Java 8 is required to compile and run.
No external dependencies to keep the tool tidy and simple.

