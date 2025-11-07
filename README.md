<!-- markdownlint-disable MD041 -->
[//]: # (auto_md_to_doc_comments segment start A)

# msg_enc_dec

[//]: # (auto_cargo_toml_to_md start)

**Use SSH keys, Ed22519, X25519 and GCM to encrypt and decrypt messages and files for communication**  
***version: 1.0.25 date: 2025-11-07 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/msg_enc_dec)***

 ![maintained](https://img.shields.io/badge/maintained-green)
 ![ready-for-use](https://img.shields.io/badge/ready_for_use-green)
 ![rustlang](https://img.shields.io/badge/rustlang-orange)

[//]: # (auto_cargo_toml_to_md end)

 ![License](https://img.shields.io/badge/license-MIT-blue.svg)
 ![Rust](https://github.com/bestia-dev/msg_enc_dec/workflows/rust_fmt_auto_build_test/badge.svg)
 ![msg_enc_dec](https://bestia.dev/webpage_hit_counter/get_svg_image/124137175.svg)

[//]: # (auto_lines_of_code start)
[![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-660-green.svg)](https://github.com/bestia-dev/msg_enc_dec/)
[![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-176-blue.svg)](https://github.com/bestia-dev/msg_enc_dec/)
[![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-80-purple.svg)](https://github.com/bestia-dev/msg_enc_dec/)
[![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/bestia-dev/msg_enc_dec/)
[![Lines in tests](https://img.shields.io/badge/Lines_in_tests-0-orange.svg)](https://github.com/bestia-dev/msg_enc_dec/)

[//]: # (auto_lines_of_code end)

Hashtags: #maintained #ready-for-use #rustlang  
My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).  

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!  
USE AT YOUR OWN RISK!

## Try it

For encrypted communication between two parties, both parties must use msg_enc_dec.  
Install msg_enc_dec from GitHub.  
It is preferred to use Rust locally to build the program, so you know exactly the source code and you can review it.  
I use the [CRUSTDE](https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod) container to run Rust programs inside an isolated environment to not compromise my base operating system.  

## On Linux

Linux everywhere!  
On Linux (I use Debian inside [WSL on Windows](https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod)):  

```bash
cd ~/rustprojects
git clone git@github.com:bestia-dev/msg_enc_dec.git
code msg_enc_dec
cargo auto release
alias msg_enc_dec="./target/release/msg_enc_dec"
msg_enc_dec --help
```

![image_01](images/image_01.png)  
![image_02](images/image_02.png)

## Development details

Read the development details in a separate md file:
[DEVELOPMENT.md](DEVELOPMENT.md)

## Releases changelog

Read the releases changelog in a separate md file:
[RELEASES.md](RELEASES.md)

## TODO

and code happy ever after

## Open-source and free as a beer

My open-source projects are free as a beer (MIT license).  
I just love programming.  
But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
You know the price of a beer in your local bar ;-)  
So I can drink a free beer for your health :-)  
[Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻

[//bestia.dev](https://bestia.dev)  
[//github.com/bestia-dev](https://github.com/bestia-dev)  
[//bestiadev.substack.com](https://bestiadev.substack.com)  
[//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  

[//]: # (auto_md_to_doc_comments segment end A)
