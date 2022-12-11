use hmac::Hmac;
use hmac::Mac;
use sha1::Sha1;
use std::time::SystemTime;
use data_encoding::BASE32;
use std::time::Duration;
use std::io;

static DIGITS_POWER: [u32; 9] = [1,10,100,1000,10000,100000,1000000,10000000,100000000];

fn get_current_time() -> u64 {
    return SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
}

fn hex_string_to_bytes(hex: String) -> Vec<u8> {
    let bytes = hex[..].as_bytes();
    return BASE32.decode(bytes).expect("Decoded bytes");
}

fn hmac_sha<D>(key_bytes: Vec<u8>, text: Vec<u8>) -> Vec<u8> {
    let mac = Hmac::<Sha1>::new_from_slice(&key_bytes[..]).expect("Hmac?");
    return mac.chain_update(text)
        .finalize()
        .into_bytes()
        .to_vec();
}

fn generate_totp<D>(key: Vec<u8>, time: Vec<u8>, return_digits: usize) -> String {
    let hash = hmac_sha::<D>(key, time);
    let offset = usize::from(hash.last().expect("Need a byte") & 0xf);
    let binary =
             (u32::from(hash[offset] & 0x7f) << 24) |
             (u32::from(hash[offset + 1 & 0xff]) << 16) |
             (u32::from(hash[offset + 2 & 0xff]) << 8) |
             u32::from(hash[offset + 3] & 0xff);
    let otp = binary % DIGITS_POWER[return_digits];
    return format!("{:0digits$}", otp, digits = return_digits);
}

fn main() {
    let secret = io::stdin().lines().next().unwrap().expect("secret");

    let code_digits = 6;
    let step = 30;
    let duration = get_current_time();
    let t = duration / step;
    let msg = t.to_be_bytes().to_vec();
    let k = hex_string_to_bytes(secret);
    let otp = generate_totp::<Sha1>(k, msg, code_digits);
    println!("{:}", otp);
}
