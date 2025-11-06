# Development details of msg_enc_dec

## CRUSTDE - Containerized Rust Development Environment

I recommend using the CRUSTDE - Containerized Rust Development Environment to write Rust projects. Follow the instructions here <https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod>.  

It is an isolated development environment that will not mess with you system.
It will work on Linux (tested on Debian) and inside WSL (Windows Subsystem for Linux).

You just need to install the newer alternative to Docker: [podman](https://podman.io/). Then you download the prepared container image from DockerHub (3GB). And then a little juggling with ssh keys. All this is simplified by running a few bash scripts. Just follow the easy instructions.  

The container image contains cargo, rustc, wasm-pack, basic-http-server, cargo-auto and other utils that a Rust project needs.  

## Workflow with automation_tasks_rs and cargo-auto

For easy workflow, use the automation tasks that are already coded in the sub-project `automation_tasks_rs`. This is a basic workflow:

```bash
cargo auto build
cargo auto release
cargo auto doc
cargo auto test
cargo auto commit_and push
cargo auto github_new_release
```

Every task finishes with instructions how to proceed.  
The [cargo-auto](https://github.com/automation-tasks-rs/cargo-auto) and [dev_bestia_cargo_completion](https://github.com/automation-tasks-rs/dev_bestia_cargo_completion) are already installed inside the CRUSTDE container.

You can open the automation sub-project in VSCode and then code your own tasks in Rust.

```bash
code automation_tasks_rs
```

## super simple argument parsing

I use a super simple code to parse CLI arguments inside the `src/bin/msg_enc_dec/main.rs`. There are crate libraries that enable very complex argument parsing if needed.

## Markdown

README.md and all the doc-comments are in markdown. To separate paragraphs in markdown use an empty line between them.  
I tried other variants like double-space or backslash, but an empty line is the most used in the wild.  
Inside doc-comments 'triple slash' I use to end the line with double space and backslash. It works everywhere, also in code auto-completion.  

## Error handling thiserror and anyhow

Rule number one is never to use `.unwrap()` in your real Rust code. It is a sign, you are not Error handling properly.
Maybe `unwrap()` can be fine for some fast learning examples, but for any real-life Rust code, you must use some `Error handling`. There are many different ways to do that in Rust. I choose the pair of libraries `thiserror` and `anyhow`. The first is made for libraries, the second is made for bin-executables.  
The library needs an Enum with all the possible errors that this library can return. With `#[derive(Error)]` this enum gets everything needed to be a true Rust error struct. Every error can have a formatting string and a struct of data.  
The bin-executable does not want to be involved in every possible error separately. It needs an umbrella for all possible errors with `anyhow::Result`.  
Inside the code, mostly propagate the errors with the `?` Operator after the `Result` value instead of unwrap() or the match expression.
In the tests we don't want to work with Error handling. There, instead of `.unwrap()`, use the similar function `.expect(&str)` that has an additional description string. I use expect() when I am 100% sure the panic cannot happen because I checked some conditions before it.  

## Windows git-bash

This CLI program can run in `windows git-bash`. This environment has also other names like: cygwin, msys2, msys64, MingW64, git-for-windows, msys or msysGit.

## Cryptography

Cryptography is a technique of securing information and communications using codes to ensure confidentiality, integrity and authentication.  
Modern ciphers, such as the Advanced Encryption Standard (AES), are considered virtually unbreakable.  
Secret key cryptography, also known as symmetric encryption, uses a single key to encrypt and decrypt a message.  
Public key cryptography (PKC), or asymmetric cryptography, uses mathematical functions to create codes that are exceptionally difficult to crack. It enables people to communicate securely over a non-secure communications channel without the need for a secret key.  
<https://www.fortinet.com/resources/cyberglossary/what-is-cryptography>

## OpenSSH

OpenSSH is the premier connectivity tool for remote login with the SSH protocol. It encrypts all traffic to eliminate eavesdropping, connection hijacking, and other attacks.  
Key management with ssh-add, ssh-keysign, ssh-keyscan, and ssh-keygen, ssh-agent.  
<https://www.openssh.com/>

Open SSH uses Ed22519 for authentication. The SSH servers has a list of public keys that are authorized. The handshake: The server sends a random message. The client signs it with the private key Ed25519. The SSH server verifies the signature with the public key Ed25519.

OpenSSH comes with tools to manage keys and it is a knowledge every developer learns early and thoroughly. The private key is protected by a passphrase. For repetitive use of the same private key I can use ssh-agent to input the passphrase only once. Usually the key inside ssh-agent is time limited for example for one hour.

## bestia.dev

I use Ed25519 to store encrypted values on the local disk. First I create random 32 bytes called the 'seed'. I sign it with the private key Ed25519. That becomes the password I use to symmetrically encrypt GCM the secret value. In the saved file there is in plain text the seed and the encrypted data. Only the owner of the private key Ed25519 can sign the seed to get the password to then decrypt GCM the data.

## Ed25519

Ed25519 is the EdDSA signature scheme using SHA-512 (SHA-2) and an elliptic curve related to Curve25519.  
In public-key cryptography, Edwards-curve Digital Signature Algorithm (EdDSA) is a digital signature scheme using a variant of Schnorr signature based on twisted Edwards curves. It is designed to be faster than existing digital signature schemes without sacrificing security.  
Public keys are 256 bits long and signatures are 512 bits long.  
<https://en.wikipedia.org/wiki/EdDSA#Ed25519>

Ed25519 is a signature scheme. It does not do encryption.  

## X25519

X25519 is the name given to the Elliptic Curve Diffie-Hellman (ECDH) key exchange built on Ed22519.  
<https://medium.com/@aditrizky052/unlocking-the-power-of-curve25519-ed25519-x25519-the-modern-pillars-of-secure-and-high-speed-a3daefbad0a4>

The Diffie-Hellman algorithm (DH) is used for secret key exchanges and requires two people to agree on a large prime number.  
Key Exchange Algorithm KEA is a variation of the Diffie-Hellman algorithm and was proposed as a method for key exchange.  
<https://www.fortinet.com/resources/cyberglossary/what-is-cryptography>

## GCM

In cryptography, Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance. The GCM algorithm provides data authenticity, integrity and confidentiality and belongs to the class of authenticated encryption with associated data (AEAD) methods.  
<https://en.wikipedia.org/wiki/Galois/Counter_Mode>  

## Base64

In computer programming, Base64 is a group of binary-to-text encoding schemes that transforms binary data into a sequence of printable characters, limited to a set of 64 unique characters. More specifically, the source binary data is taken 6 bits at a time, then this group of 6 bits is mapped to one of 64 unique characters.  
The particular set of 64 characters chosen to represent the 64-digit values for the base varies between implementations. The general strategy is to choose 64 characters that are common to most encodings and that are also printable. For example, MIME's Base64 implementation uses A–Z, a–z, and 0–9 for the first 62 values. Other variations share this property but differ in the symbols chosen for the last two values.  
The base64url RFC 4648 §5 standard is URL and filename-safe, where the '+' and '/' characters are replaced by '-' and '_'.  
The = symbol is also used as a padding suffix. The padding character is not essential for decoding, since the number of missing bytes can be inferred from the length of the encoded text. In some implementations, the padding character is mandatory, while for others it is not used.
<https://en.wikipedia.org/wiki/Base64>

## Debug with tracing and log to file

For debugging purposes the program has tracing and log to file.  
If the environment variable MSG_ENC_DEC_LOG exists than the tracing to file is enabled.  
The log is appended to files in the local `logs/` folder.  
In the env var MSG_ENC_DEC_LOG we can define filters.  
A filter consists of one or more comma-separated directives
target[span{field=value}]=level
Levels order: 1. ERROR, 2. WARN, 3. INFO, 4. DEBUG, 5. TRACE
ERROR level is always logged.
Example of filter for a single execution:

```bash
MSG_ENC_DEC_LOG="debug,hyper_util=info,reqwest=info" ./{package_name}
```
