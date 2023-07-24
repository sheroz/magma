// Test vectors GOST R 34.13-2015
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf

pub const CIPHER_KEY: [u32; 8] = [
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
];

pub const PLAINTEXT1: u64 = 0x92def06b3c130a59_u64;
pub const PLAINTEXT2: u64 = 0xdb54c704f8189d20_u64;
pub const PLAINTEXT3: u64 = 0x4a98fb2e67a8024c_u64;
pub const PLAINTEXT4: u64 = 0x8912409b17b57e41_u64;

// Test vectors GOST R 34.13-2015
// Encrypting in ECB Mode
// Page 35, Section: A.2.1
pub const CIPHERTEXT1_ECB: u64 = 0x2b073f0494f372a0_u64;
pub const CIPHERTEXT2_ECB: u64 = 0xde70e715d3556e48_u64;
pub const CIPHERTEXT3_ECB: u64 = 0x11d8d9e9eacfbc1e_u64;
pub const CIPHERTEXT4_ECB: u64 = 0x7c68260996c67efb_u64;

// Test vectors GOST R 34.13-2015
// Encrypting in CTR Mode
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
// Page 36, Section A.2.2
pub const CIPHERTEXT1_CTR: u64 = 0x4e98110c97b7b93c_u64;
pub const CIPHERTEXT2_CTR: u64 = 0x3e250d93d6e85d69_u64;
pub const CIPHERTEXT3_CTR: u64 = 0x136d868807b2dbef_u64;
pub const CIPHERTEXT4_CTR: u64 = 0x568eb680ab52a12d_u64;

// Test vectors GOST R 34.13-2015
// Encrypting in OFB Mode
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
// Page 37, Section A.2.3
pub const CIPHERTEXT1_OFB: u64 = 0xdb37e0e266903c83_u64;
pub const CIPHERTEXT2_OFB: u64 = 0x0d46644c1f9a089c_u64;
pub const CIPHERTEXT3_OFB: u64 = 0xa0f83062430e327e_u64;
pub const CIPHERTEXT4_OFB: u64 = 0xc824efb8bd4fdb05_u64;

// Test vectors GOST R 34.13-2015
// Encrypting in CBC Mode
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
// Page 38, Section A.2.4
pub const CIPHERTEXT1_CBC: u64 = 0x96d1b05eea683919_u64;
pub const CIPHERTEXT2_CBC: u64 = 0xaff76129abb937b9_u64;
pub const CIPHERTEXT3_CBC: u64 = 0x5058b4a1c4bc0019_u64;
pub const CIPHERTEXT4_CBC: u64 = 0x20b78b1a7cd7e667_u64;

// Test vectors GOST R 34.13-2015
// Encrypting in CFB Mode
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
// Page 39, Section A.2.5
pub const CIPHERTEXT1_CFB: u64 = 0xdb37e0e266903c83_u64;
pub const CIPHERTEXT2_CFB: u64 = 0x0d46644c1f9a089c_u64;
pub const CIPHERTEXT3_CFB: u64 = 0x24bdd2035315d38b_u64;
pub const CIPHERTEXT4_CFB: u64 = 0xbcc0321421075505_u64;

// Test vectors GOST R 34.13-2015
// Generating MAC
// https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
// Page 40, Section A.2.6
pub const MAC: u32 = 0x154e7210_u32;
