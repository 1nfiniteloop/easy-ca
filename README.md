# easy-ca

## Overview

`easy-ca` is intended to be a convenient tool for easily run your own
Certificate Authority and provision x509/SSL certificates, both manually and
automatically. The tool uses the openssl library and is written in dlang.

`easy-ca` provides an alternative of using openssl commandline tool which
requires comprehensive configurations and knowledge before you can start
provision certificates. This tool also serves as a base for provisioning
certificates automatically. It uses JSON-format exclusively through the entire
application and could easily be integrated into a webserer for example.

Future work, roadmap:

* Implement webserver for automatic certificate provisioning.
* Implement certificate revocation.

## License

MIT

## Build & install

### Preparation

* Docker is installed.
* All dependencies is installed; on ubuntu `sudo apt-get install openssl` which
  also includes the library `libssl1.1` required by `easy-ca`.

### Steps

1. Create the build-environment with:
   `docker build --tag=easy-ca-builder:1.0.0 .devcontainer/`.
2. Compile the application:
   ```bash
   docker run \
        --rm \
        --workdir=/home/build \
        --volume=$(pwd):/home/build \
        --name=easy-ca-builder \
        --user=$(id -u):$(id -g) \
        easy-ca-builder:1.0.0 \
        /bin/bash -c 'dub build --build=release'
   ```
3. Install the compiled binary with `sudo install easy-ca /usr/local/bin`.
4. Install configuration files with `sudo cp --recursive config /etc/easy-ca`.

## Usage

These steps describes how to manually set up your own Certificate authority
and sign certificates. Some notes:

* The tool uses a naming convention when creating and reading files. 
* If an RSA key does not exists, it will be created.

### Create Root Certificate Authority

The root certificate and key shall preferably be safely stored offline.

1. Set path to storage location with: 
   `ca_root=/media/${USER}/<media-device>/easy-ca/ca` and create directory
   structure with `mkdir --parents ${ca_root}`.
2. Create the subject as a json-formatted file `${ca_root}/<name>.subject.json`
   where the name is `ca.root`, example below:
   ```json
   {
       "C":  "SE",
       "ST": "Gothenburg",
       "O":  "World Wide Web Inc.",
       "OU": "World Wide Web Inc. Certificate Authority",
       "CN": "World Wide Web Inc. Root CA"
   }
   ```
3. Create the root certificate and rsa key with
   `easy-ca --self-sign --path=${ca_root} --template=CA_ROOT ca.root`.
4. Two new files has now been created: `${ca_root}/ca.root.cert.pem` and 
   `${ca_root}/ca.root.key.pem`.

### Create Intermediate Certificate Authority

This step describes how to create an intermediate CA used for signing
certificates on behalf of the root ca.

1. Set path to storage location with: `ca_intermediate=~/.easy-ca/ca` and create
   directory structure with: `mkdir --parents ${ca_intermediate}`.
3. Create the subject in a json-formatted file
   `${ca_intermediate}/<name>.subject.json` where the name is `ca.intermediate`.
   **Note:** Make sure the subject follows the ca-policy configured in
   `ca_policies.json`.
4. Create the certificate signing request and rsa key:
   `easy-ca --new-csr --path=${ca_intermediate} --template=CA_INTERMEDIATE ca.intermediate`.
   **Note** The rsa key bits is provided from configuration-file
   `csr_config.json` if template is provided, else default 2048 bits is used.
5. Create the intermediate certificate using the root certificate authority:
   `easy-ca --sign --ca-path=${ca_root} --ca-name=ca.root --template=CA_INTERMEDIATE --path=${ca_intermediate} ca.intermediate`. 
6. Three new files has now been created: `ca.intermediate.key.pem`,
   `ca.intermediate.csr.pem` and `ca.intermediate.cert.pem`.
7. Create the certificate chain file manually:
   `cat ${ca_intermediate}/*.cert.pem ${ca_root}/*.cert.pem > ${ca_intermediate}/ca.intermediate.ca-chain.pem`.

### Create a server certificate

This step describes how to create a certificate signed by our intermediate ca.

1. Create the subject in a json-formatted file `<name>.subject.json` where the
   name is example `www.example.com`. **Note:** Make sure the subject follows
   the policy configured in `ca_policies.json`.
2. Create a certificate signing request and rsa key:
   `easy-ca --new-csr --template=SERVER www.example.com`.
3. Create the server certificate by using the `ca.intermediate` ca for signing:
   `easy-ca --sign --ca-path=${ca_intermediate} --ca-name=ca.intermediate --template=SERVER www.example.com`.
4. Three new files has now been created: `www.example.com.key.pem`, 
   `www.example.com.csr.pem` and `www.example.com.cert.pem`.

### Inspect and verify

The files created from commands above can be inspected with openssl:

* RSA Key: `openssl rsa -noout -text -in path/to/*.key.pem`.
* Certificate: `openssl x509 -noout -text -in path/to/*.cert.pem`.
* Certificate Signing Request: `openssl req -noout -text -in path/to/*.csr.pem`.

The certificates can be verified with openssl:

* Verify intermediate certificate:
  `openssl verify -CAfile ${ca_root}/ca.root.cert.pem ${ca_intermediate}/ca.intermediate.cert.pem`.
* Verify server/client certificates:
  `openssl verify -CAfile ${ca_intermediate}/ca.intermediate.ca-chain.pem www.example.com.cert.pem`.

## Contributing

### Development environment

This project is developed in Visual Studio Code (VS Code) "insiders"
<https://code.visualstudio.com/insiders/>. Currently (at the time of writing)
only this pre-release version supports the plugin "remote development". This
plugin makes it possible to have the development environment inside a
container, see more @ <https://code.visualstudio.com/docs/remote/containers>.

To setup the development environment you just need to open this project in VS
Code and a notification appears where you can choose to open the project inside
a container. All the tools and dependencies will be installed and set-up
accordingly to what's specified in the `.devcontainer/Dockerfile`. No further
dependencies, tools or library installations is needed, the only prerequisite
on the host is that Docker is installed.

## References

* Awesome guide for how to run a Certificate Authority using openssl -
  <https://jamielinux.com/docs/openssl-certificate-authority/>
