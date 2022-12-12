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
    let bytes = hex.as_bytes();
    return BASE32.decode(bytes)
        .expect("decoding hex string");
}

fn hmac_sha<D>(key_bytes: Vec<u8>, text: Vec<u8>) -> Vec<u8> {
    let mac = Hmac::<Sha1>::new_from_slice(&key_bytes)
        .expect("Mac from key_bytes");
    return mac.chain_update(text)
        .finalize()
        .into_bytes()
        .to_vec();
}

fn generate_totp<D>(key: Vec<u8>, time: Vec<u8>, return_digits: usize) -> String {
    let hash = hmac_sha::<D>(key, time);
    let offset_byte = 0xf & hash.last()
        .expect("Hash needs to not be empty");
    let offset = usize::from(offset_byte);
    let bytes = hash[offset..offset+4]
        .try_into()
        .expect("Bytes");
    let binary = u32::from_be_bytes(bytes) & 0x7fff_ffff;
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
