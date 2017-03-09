# wowza-letsencrypt-converter

Simple utility to convert all let's encrypt certificates to JKS store and create a domain to keystore map for Wowza Streaming Engine (4.5.0+).

Wowza Streaming Engine can reload domain mapped keystores when the keystore map file changes, so running this converter utility after certificate renewals (or after adding or removing certificates) will let a running server reinitialize its certificate store with the updated certificates.
 
## Compile

```Shell
gradle jar
```

## Usage

```Shell
java -jar wowza-letsencrypt-converter-0.1.jar [-v] <output-path> [<letsencrypt-live-path>] 
```

The  *letsencrypt-live-path* parameter defaults to /etc/letsencrypt/live, as is in common Linux systems, might be different on others. The *output-path* must be an existing and writable directory, here a new JKS keystore will be created for every certificate in the input directory together with a file jksmap.txt containing the domain to keystore mapping to be used in the VHost.xml of Wowza Streaming Engine.

The generated JKS password will be 'secret'.

Feel free to fork if you need additional functionality.

## Real life

Tested on Amazon Linux with Wowza Streaming Engine 4.6.0.

## License

Licensed under the MIT license. 
 
## Requirements

Java 8 is required to compile and run.
No external dependencies to keep the tool tidy and simple.

