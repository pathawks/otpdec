use hmac::Hmac;
use hmac::Mac;
use sha1::Sha1;
use std::time::SystemTime;
use data_encoding::BASE32;
use data_encoding::HEXUPPER;
use std::io;

type HmacSha1 = Hmac<Sha1>;

static DIGITS_POWER: [u32; 9] = [1,10,100,1000,10000,100000,1000000,10000000,100000000];

fn main() {
    let secret = io::stdin().lines().next().unwrap().expect("secret");

    let code_digits = 6;
    let step = 30;
    let duration = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    };
    let t = duration / step;
    let formatted_sec = HEXUPPER.encode(&t.to_be_bytes()).into_bytes();
    let message = hex::decode(formatted_sec).expect("This better be bytes");
    let key_bytes = &BASE32.decode(secret[..].as_bytes()).expect("Decoded bytes")[..];
    let mac = HmacSha1::new_from_slice(key_bytes).expect("Hmac?");
    let ff = mac.chain_update(message).finalize();
    let hash = ff.into_bytes();
    let offset = usize::from(hash.last().expect("Need a byte") & 0xf);
    let binary =
             (u32::from(hash[offset] & 0x7f) << 24) |
             (u32::from(hash[offset + 1] & 0xff) << 16) |
             (u32::from(hash[offset + 2] & 0xff) << 8) |
             u32::from(hash[offset + 3] & 0xff);
    let otp = binary % DIGITS_POWER[code_digits];
    println!("{:06}", otp);
}
