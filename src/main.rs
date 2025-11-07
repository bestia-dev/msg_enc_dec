//! src/bin/msg_enc_dec/main.rs

// region: auto_md_to_doc_comments include README.md A //!
//! # msg_enc_dec
//!
//! **Use SSH keys, Ed22519, X25519 and GCM to encrypt and decrypt messages and files for communication**  
//! ***version: 1.0.25 date: 2025-11-07 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/bestia-dev/msg_enc_dec)***
//!
//!  ![maintained](https://img.shields.io/badge/maintained-green)
//!  ![ready-for-use](https://img.shields.io/badge/ready_for_use-green)
//!  ![rustlang](https://img.shields.io/badge/rustlang-orange)
//!
//!  ![License](https://img.shields.io/badge/license-MIT-blue.svg)
//!  ![Rust](https://github.com/bestia-dev/msg_enc_dec/workflows/rust_fmt_auto_build_test/badge.svg)
//!  ![msg_enc_dec](https://bestia.dev/webpage_hit_counter/get_svg_image/124137175.svg)
//!
//! [![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-660-green.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-176-blue.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-80-purple.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//! [![Lines in tests](https://img.shields.io/badge/Lines_in_tests-0-orange.svg)](https://github.com/bestia-dev/msg_enc_dec/)
//!
//! Hashtags: #maintained #ready-for-use #rustlang  
//! My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).  
//!
//! ## ⚠️ Security Warning
//!
//! The implementation contained in this crate has never been independently audited!  
//! USE AT YOUR OWN RISK!
//!
//! ## Try it
//!
//! For encrypted communication between two parties, both parties must use msg_enc_dec.  
//! Install msg_enc_dec from GitHub.  
//! It is preferred to use Rust locally to build the program, so you know exactly the source code and you can review it.  
//! I use the [CRUSTDE](https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod) container to run Rust programs inside an isolated environment to not compromise my base operating system.  
//!
//! ## On Linux
//!
//! Linux everywhere!  
//! On Linux (I use Debian inside [WSL on Windows](https://github.com/CRUSTDE-ContainerizedRustDevEnv/crustde_cnt_img_pod)):  
//!
//! ```bash
//! cd ~/rustprojects
//! git clone git@github.com:bestia-dev/msg_enc_dec.git
//! code msg_enc_dec
//! cargo auto release
//! alias msg_enc_dec="./target/release/msg_enc_dec"
//! msg_enc_dec --help
//! ```
//!
//! ![image_01](images/image_01.png)  
//! ![image_02](images/image_02.png)
//!
//! ## Development details
//!
//! Read the development details in a separate md file:
//! [DEVELOPMENT.md](DEVELOPMENT.md)
//!
//! ## Releases changelog
//!
//! Read the releases changelog in a separate md file:
//! [RELEASES.md](RELEASES.md)
//!
//! ## TODO
//!
//! and code happy ever after
//!
//! ## Open-source and free as a beer
//!
//! My open-source projects are free as a beer (MIT license).  
//! I just love programming.  
//! But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
//! You know the price of a beer in your local bar ;-)  
//! So I can drink a free beer for your health :-)  
//! [Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻
//!
//! [//bestia.dev](https://bestia.dev)  
//! [//github.com/bestia-dev](https://github.com/bestia-dev)  
//! [//bestiadev.substack.com](https://bestiadev.substack.com)  
//! [//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  
//!
// endregion: auto_md_to_doc_comments include README.md A //!

mod encrypt_decrypt_with_ssh_key_mod;

use anyhow::Context;
use encrypt_decrypt_with_ssh_key_mod::encrypt_decrypt_mod as ende;

// region: Public API constants
// ANSI colors for Linux terminal
// https://github.com/shiena/ansicolor/blob/master/README.md
/// ANSI color
pub const RED: &str = "\x1b[31m";
/// ANSI color
#[allow(dead_code)]
pub const GREEN: &str = "\x1b[32m";
/// ANSI color
pub const YELLOW: &str = "\x1b[33m";
/// ANSI color
#[allow(dead_code)]
pub const BLUE: &str = "\x1b[34m";
/// ANSI color
pub const RESET: &str = "\x1b[0m";
// endregion: Public API constants

use crossplatform_path::CrossPathBuf;

// import trait
use secrecy::{ExposeSecret, SecretBox, SecretString};
#[allow(unused_imports)]
use tracing::{debug, error, info};

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct MsgEncDecConfig {
    pub msg_enc_dec_private_key_file_name: String,
}

/// Path of the config file
pub static CONFIG_PATH: &str = "msg_enc_dec_config.json";

/// Application state (static OnceLock) is initialized only once in the main() function.
///
/// And then is read/write accessible all over the code. Thread safe.
pub static MSG_ENC_DEC_CONFIG: std::sync::OnceLock<MsgEncDecConfig> = std::sync::OnceLock::new();

/// Struct that represents the json data saved in the '*.enc' file.
#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct EncryptedTextWithMetadata {
    pub(crate) plain_seed_string: String,
    pub(crate) plain_encrypted_text: String,
}

/// Function main() returns ExitCode.
fn main() -> std::process::ExitCode {
    match main_returns_anyhow_result() {
        Err(err) => {
            eprintln!("{}", err);
            // eprintln!("Exit program with failure exit code 1");
            std::process::ExitCode::FAILURE
        }
        Ok(()) => std::process::ExitCode::SUCCESS,
    }
}

/// Function main() returns anyhow::Result.
fn main_returns_anyhow_result() -> anyhow::Result<()> {
    tracing_init()?;
    msg_enc_dec_config_initialize().log(pos!())?;
    // super simple argument parsing. There are crates that can parse more complex arguments.
    match std::env::args().nth(1).as_deref() {
        None | Some("--help") | Some("-h") => print_help().log(pos!())?,
        // Register completion for msg_enc_dec  with the shell command 'complete -C'.
        Some("register_completion") => register_completion().log(pos!())?,
        // When registered completion calls msg_enc_dec, the first argument is the path of the program.
        // Completion will react only on 'msg_enc_dec' as first word. Not ./msg_enc_dec or ~/msg_enc_dec,...
        Some("msg_enc_dec") => msg_enc_dec_completion().log(pos!())?,
        Some("create_ssh_key") => create_ssh_key().log(pos!())?,
        Some("send_public_key") => send_public_key().log(pos!())?,
        Some("receive_public_key") => receive_public_key().log(pos!())?,
        Some("message_encrypt") => message_encrypt().log(pos!())?,
        Some("message_decrypt") => message_decrypt().log(pos!())?,

        Some("file_encrypt") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                file_encrypt(file_name).log(pos!())?;
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },
        Some("file_decrypt") => match std::env::args().nth(2).as_deref() {
            // second argument
            Some(file_name) => {
                file_decrypt(file_name).log(pos!())?;
            }
            None => eprintln!("{RED}Error: Missing arguments `file_name`.{RESET}"),
        },

        _ => eprintln!("{RED}Error: Unrecognized arguments. Try `msg_enc_dec --help`{RESET}"),
    }
    Ok(())
}

/// macro to get source code position to log errors before propagation
///
/// example:  read_to_string("x").log(pos!())?;
macro_rules! pos {
    // `()` indicates that the macro takes no argument.
    () => {
        // The macro will expand into the contents of this block.
        &format!("{}:{}:{}:", file!(), line!(), column!())
    };
}
pub(crate) use pos;

/// Trait to log the error from Result before propagation with ?.
pub trait ResultLogError<T, E>: Sized {
    fn log(self, file_line_column: &str) -> Self;
}

/// Implements LogError for anyhow::Result.
impl<T, E: std::fmt::Debug> ResultLogError<T, E> for core::result::Result<T, E> {
    fn log(self, file_line_column: &str) -> Self {
        self.inspect_err(|err| tracing::error!("{} {:?}", file_line_column, err))
    }
}

/// Initialize tracing to file logs/msg_enc_dec.log.  \
///
/// The folder logs/ is in .gitignore and will not be committed.  
pub fn tracing_init() -> anyhow::Result<()> {
    let offset = time::UtcOffset::current_local_offset()?;
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        offset,
        time::macros::format_description!("[hour]:[minute]:[second].[subsecond digits:6]"),
    );

    // A filter consists of one or more comma-separated directives
    // target[span{field=value}]=level
    // Levels order: 1. ERROR, 2. WARN, 3. INFO, 4. DEBUG, 5. TRACE
    // ERROR level is always logged.
    // Add filters to MSG_ENC_DEC_LOG environment variable for a single execution:
    // ```bash
    // MSG_ENC_DEC_LOG="debug,hyper_util=info,reqwest=info" ./{package_name}
    // ```
    let filter = tracing_subscriber::EnvFilter::from_env("MSG_ENC_DEC_LOG");

    let builder = tracing_subscriber::fmt()
        .with_file(true)
        .with_timer(timer)
        .with_line_number(true)
        .with_ansi(false)
        .with_env_filter(filter);
    if std::env::var("MSG_ENC_DEC_LOG").is_ok() {
        // if MSG_ENC_DEC_LOG exists than enable tracing to file
        let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("msg_enc_dec")
            .filename_suffix("log")
            .build("logs")
            .expect("initializing rolling file appender failed");
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    };

    Ok(())
}

/// Application state (static) is initialized only once in the main() function.
///
/// And then is accessible all over the code.
fn msg_enc_dec_config_initialize() -> anyhow::Result<()> {
    if MSG_ENC_DEC_CONFIG.get().is_some() {
        return Ok(());
    }

    let config_path = CrossPathBuf::new(CONFIG_PATH).log(pos!())?;
    if !config_path.exists() {
        config_path
            .write_str_to_file(
                r#"
{
"msg_enc_dec_private_key_file_name":"msg_enc_dec_ssh_1"
}   
"#,
            )
            .log(pos!())?;
    }

    let msg_enc_dec_config_json = config_path.read_to_string().log(pos!())?;
    let msg_enc_dec_config: MsgEncDecConfig = serde_json::from_str(&msg_enc_dec_config_json).log(pos!())?;
    MSG_ENC_DEC_CONFIG
        .set(msg_enc_dec_config)
        .expect("Static OnceLock should not error for set().");

    Ok(())
}

/// Print help to the terminal.
fn print_help() -> anyhow::Result<()> {
    println!(
        r#"
  {YELLOW}Welcome to msg_enc_dec CLI {RESET}

  Use SSH keys, Ed22519, X25519 and GCM to encrypt and decrypt messages and files for communication.
  Use ssh private key Ed22519 to encrypt and save locally the shared secret token.
  Use symmetric encryption GCM to encrypt and decrypt messages and files
  for secure communication between two users.

  This is the help for this program.
{GREEN}msg_enc_dec --help {RESET}
  
  Register bash completion for msg_enc_dec.
{GREEN}msg_enc_dec register_completion {RESET}

  {YELLOW}INITIALIZATION {RESET}

  Do it only once. Create your ssh key if you don't have it already. 
  Give it a good passphrase and remember it. 
  Nobody can help you if you forget it. 
  You would have to delete the old key and create a new one.
  This ssh key will be used to save locally the secret session token for the communication.
{GREEN}msg_enc_dec create_ssh_key {RESET}

  {YELLOW}HANDSHAKE {RESET}

  You can use ssh-agent to type the passphrase of the ssh private key only once for one hour.
{GREEN}ssh-add -t 1h msg_enc_dec_ssh_1 {RESET}

  Create a new static key-pair X25519 and send the public key to the other party. 
  It is not a secret. You can use any communication available: email, whatsapp, messenger, sms,...
  Both users must send their public key to the other user.
{GREEN}msg_enc_dec send_public_key {RESET}

  Receive the other's public key and calculate the shared secret.
  Save the encrypted shared secret for later use.
{GREEN}msg_enc_dec receive_public_key {RESET}

  {YELLOW}COMMUNICATION {RESET}

  Encrypt message and send the encrypted text.
{GREEN}msg_enc_dec message_encrypt {RESET}
  Decrypt the received message.
{GREEN}msg_enc_dec message_decrypt {RESET}
  Encrypt file and send the encrypted file.
{GREEN}msg_enc_dec file_encrypt file_name {RESET}
  Decrypt the received file.
{GREEN}msg_enc_dec file_decrypt file_name{RESET}

  {YELLOW}© 2025 bestia.dev  MIT License github.com/bestia-dev/msg_enc_dec {RESET}
"#
    );
    Ok(())
}

/// Register completion with the bash command complete.
fn register_completion() -> anyhow::Result<()> {
    println!("Run this command manually to register completion in this bash session:");
    println!("{GREEN}complete -C msg_enc_dec msg_enc_dec{RESET}");
    println!("If you want the completion to persist in future bash sessions, add the command to your ~/.bashrc file.");
    Ok(())
}

/// Sub-command for bash auto-completion of `msg_enc_dec`.
fn msg_enc_dec_completion() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let word_being_completed = args[2].as_str();

    let sub_commands = vec![
        "create_ssh_key",
        "send_public_key",
        "receive_public_key",
        "message_encrypt",
        "message_decrypt",
        "file_encrypt",
        "file_decrypt",
    ];
    completion_return_one_or_more_sub_commands(sub_commands, word_being_completed);
    Ok(())
}

/// Print one or more sub_commands.
pub fn completion_return_one_or_more_sub_commands(sub_commands: Vec<&str>, word_being_completed: &str) {
    let mut sub_found = false;
    for sub_command in sub_commands.iter() {
        if sub_command.starts_with(word_being_completed) {
            println!("{sub_command}");
            sub_found = true;
        }
    }
    if !sub_found {
        // print all sub-commands
        for sub_command in sub_commands.iter() {
            println!("{sub_command}");
        }
    }
}

/// Create ssh key and config json.
fn create_ssh_key() -> anyhow::Result<()> {
    // instead of using ssh-keygen, I will create the private and public key in Rust code using ed25519-dalek

    println!("  {YELLOW}Generate the ssh private/public key pair. {RESET}");
    println!("  {YELLOW}Give it a good passphrase and remember it. {RESET}");
    println!("  {YELLOW}Nobody can help you if you forget the passphrase. {RESET}");
    println!("  {YELLOW}You would have to delete the old key and create a new one. {RESET}");
    println!("  {YELLOW}This ssh key will be used to save locally the secret session token for the communication. {RESET}");
    let secret_passphrase: String = dialoguer::Password::new()
        .with_prompt(format!("{BLUE}Write secret passphrase{RESET}"))
        .interact()
        .log(pos!())?;

    let private_key = ssh_key::PrivateKey::random(&mut aes_gcm::aead::OsRng, ssh_key::Algorithm::Ed25519).log(pos!())?;
    let encrypted_key = private_key.encrypt(&mut aes_gcm::aead::OsRng, secret_passphrase).log(pos!())?;
    let path = CrossPathBuf::new("msg_enc_dec_ssh_1").log(pos!())?;
    encrypted_key
        .write_openssh_file(&path.to_path_buf_current_os(), ssh_key::LineEnding::LF)
        .log(pos!())?;
    let path = CrossPathBuf::new("msg_enc_dec_ssh_1.pub").log(pos!())?;
    private_key
        .public_key()
        .write_openssh_file(&path.to_path_buf_current_os())
        .log(pos!())?;

    println!();
    println!("  {YELLOW}After create_ssh_key run 'msg_enc_dec send_public_key'. {RESET}");
    Ok(())
}

/// Print the static public key to be sent.
fn send_public_key() -> anyhow::Result<()> {
    // https://docs.rs/crate/x25519-dalek/
    // create static secret, because ephemeral secrets cannot be extracted and eaved to file.
    let static_secret: x25519_dalek::StaticSecret = x25519_dalek::StaticSecret::random();

    // Save the static secret encrypted into local folder.
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("static_secret.enc").log(pos!())?;
    encrypt_and_save_file(&private_key_file_name, static_secret.to_bytes(), &encrypted_secret_file_path).log(pos!())?;

    // Send the public key to the other party.
    let public_key = x25519_dalek::PublicKey::from(&static_secret);
    let public_key_string = ende::encode64_from_bytes_to_string(public_key.to_bytes().to_vec());

    println!("  {YELLOW}Send this public key to the other party. This is not a secret. {RESET}");
    println!("  {YELLOW}They must use 'msg_enc_dec receive_public_key'. {RESET}");
    println!("  {YELLOW}and then send you the encrypted session token. {RESET}");
    println!("  {YELLOW}It is encrypted, only the owner of the private key can decrypt it. {RESET}");
    println!(r#"{GREEN}{public_key_string} {RESET}"#);

    Ok(())
}

/// Save the secret bytes symmetrically encrypted into a file.
///
/// Use the private key to sign the random seed. The random seed is saved as plain inside the file.
/// The file is bas64 only to masquerade it a little bit.
fn encrypt_and_save_file(
    private_key_file_name: &str,
    secret_bytes: [u8; 32],
    encrypted_secret_file_path: &CrossPathBuf,
) -> Result<(), anyhow::Error> {
    let (plain_seed_bytes_32bytes, plain_seed_string) = ende::random_seed_32bytes_and_string().log(pos!())?;
    let private_key_path = CrossPathBuf::new(private_key_file_name).log(pos!())?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path, plain_seed_bytes_32bytes).log(pos!())?;
    let secret_string = secrecy::SecretString::from(ende::encode64_from_32bytes_to_string(secret_bytes).log(pos!())?);
    debug!("secret_string: {}", secret_string.expose_secret());
    let plain_encrypted_text = ende::encrypt_symmetric(secret_passcode_32bytes, secret_string).log(pos!())?;
    let json_struct = EncryptedTextWithMetadata {
        plain_seed_string,
        plain_encrypted_text,
    };
    let json_string = serde_json::to_string_pretty(&json_struct).log(pos!())?;
    encrypted_secret_file_path.write_str_to_file(&json_string).log(pos!())?;
    Ok(())
}

/// Receive public key, calculate shared secret, encrypt and store for later use.
fn receive_public_key() -> anyhow::Result<()> {
    let other_public_key: String = dialoguer::Input::new()
        .with_prompt(format!("{BLUE}Copy the public key received from the other party{RESET}"))
        .interact_text()
        .log(pos!())?;
    let other_public_key = ende::decode64_from_string_to_32bytes(&other_public_key).log(pos!())?;
    let other_public_key = x25519_dalek::PublicKey::from(other_public_key);

    // load and decrypt the static secret
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let enc_file_path = CrossPathBuf::new("static_secret.enc").log(pos!())?;
    let static_secret_bytes = load_and_decrypt(&private_key_file_name, &enc_file_path).log(pos!())?;
    let static_secret = x25519_dalek::StaticSecret::from(static_secret_bytes);

    // calculate shared secret
    let shared_secret = static_secret.diffie_hellman(&other_public_key);

    // save encrypted shared secret
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc").log(pos!())?;
    encrypt_and_save_file(&private_key_file_name, shared_secret.to_bytes(), &encrypted_secret_file_path).log(pos!())?;

    // for debugging I can write the encrypted session token that is created
    // let session_token_enc_path = CrossPathBuf::new("enc_session_token_1.txt").log(pos!())?;
    // session_token_enc_path.write_str_to_file(&plain_session_token).log(pos!())?;

    println!("  {YELLOW}The shared secret session token is saved.{RESET}");
    println!("  {YELLOW}Now you can encrypt and decrypt messages and files.{RESET}");
    println!(r#"{GREEN}msg_enc_dec message_encrypt {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec message_decrypt {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec file_encrypt file_name {RESET}"#);
    println!(r#"{GREEN}msg_enc_dec file_decrypt file_name {RESET}"#);

    Ok(())
}

// Load and decrypt secret.
fn load_and_decrypt(private_key_file_name: &str, encrypted_secret_file_path: &CrossPathBuf) -> Result<[u8; 32], anyhow::Error> {
    let encrypted_secret_file_string = encrypted_secret_file_path.read_to_string().log(pos!())?;
    let json_struct: EncryptedTextWithMetadata = serde_json::from_str(&encrypted_secret_file_string).log(pos!())?;
    let plain_seed_bytes_32bytes = ende::decode64_from_string_to_32bytes(&json_struct.plain_seed_string).log(pos!())?;
    let private_key_path = CrossPathBuf::new(private_key_file_name).log(pos!())?;
    let secret_passcode_32bytes: SecretBox<[u8; 32]> =
        ende::sign_seed_with_ssh_agent_or_private_key_file(&private_key_path, plain_seed_bytes_32bytes).log(pos!())?;
    let secret_string = ende::decrypt_symmetric(secret_passcode_32bytes, json_struct.plain_encrypted_text).log(pos!())?;
    let secret_bytes = ende::decode64_from_string_to_32bytes(secret_string.expose_secret()).log(pos!())?;
    Ok(secret_bytes)
}

/// Get private key file name from global variable.
fn global_private_key_file_name() -> Result<String, anyhow::Error> {
    let private_key_file_name = &MSG_ENC_DEC_CONFIG
        .get()
        .context("MSG_ENC_DEC_CONFIG is None")
        .log(pos!())?
        .msg_enc_dec_private_key_file_name;
    Ok(private_key_file_name.to_string())
}

/// Encrypt message from terminal.
fn message_encrypt() -> anyhow::Result<()> {
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc").log(pos!())?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path).log(pos!())?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes).log(pos!())?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));

    let secret_message: String = dialoguer::Input::new()
        .with_prompt(format!("{BLUE}Write secret message to encrypt{RESET}"))
        .interact_text()
        .log(pos!())?;
    let secret_message = SecretString::from(secret_message);
    // encrypt secret message with symmetric encryption
    let encrypted_message = ende::encrypt_symmetric(shared_secret, secret_message).log(pos!())?;
    println!("Encrypted message:");
    println!("{encrypted_message}");
    Ok(())
}

/// Decrypt message from terminal.
fn message_decrypt() -> anyhow::Result<()> {
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc").log(pos!())?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path).log(pos!())?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes).log(pos!())?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));

    let encrypted_message: String = dialoguer::Input::new()
        .with_prompt(format!("{BLUE}Write encrypted message to decrypt{RESET}"))
        .interact_text()
        .log(pos!())?;
    // decrypt secret message with symmetric encryption
    let encrypted_message = ende::decrypt_symmetric(shared_secret, encrypted_message).log(pos!())?;
    println!("Decrypted message:");
    println!("{}", encrypted_message.expose_secret());
    Ok(())
}

/// Encrypt file.
fn file_encrypt(file_name: &str) -> anyhow::Result<()> {
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc").log(pos!())?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path).log(pos!())?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes).log(pos!())?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));
    println!("Read file: {file_name}");
    let vec_u8 = std::fs::read(file_name).log(pos!())?;
    let encrypted = ende::encrypt_symmetric_from_bytes(shared_secret, vec_u8).log(pos!())?;
    println!("Saved encrypted file: {file_name}.enc");
    std::fs::write(format!("{file_name}.enc"), encrypted).log(pos!())?;
    Ok(())
}

/// Decrypt file.
fn file_decrypt(file_name: &str) -> anyhow::Result<()> {
    let private_key_file_name = global_private_key_file_name().log(pos!())?;
    let encrypted_secret_file_path = CrossPathBuf::new("shared_secret.enc").log(pos!())?;
    let shared_secret_bytes = load_and_decrypt(&private_key_file_name, &encrypted_secret_file_path).log(pos!())?;
    // just for debug
    // let shared_secret_string = ende::encode64_from_32bytes_to_string(shared_secret_bytes).log(pos!())?;
    //println!("{shared_secret_string}");
    let shared_secret = SecretBox::new(Box::new(shared_secret_bytes));
    println!("Read encrypted file: {file_name}.enc");
    let encrypted_file = std::fs::read_to_string(format!("{file_name}.enc")).log(pos!())?;
    // decrypt secret message with symmetric encryption
    let decrypted_file = ende::decrypt_symmetric_to_bytes(shared_secret, encrypted_file).log(pos!())?;
    println!("Saved decrypted file: {file_name}");
    std::fs::write(file_name, decrypted_file).log(pos!())?;
    Ok(())
}
