pub struct HmacTableBuilder {
    hmac_state: Box<Zeroizing<blake2b_simd::State>>,
    hmac_prefixes: Vec<Box<Zeroizing<blake2b_simd::State>>>,
    buffer: Vec<u8>,

    position: usize,
}

pub struct HmacTableChecker {

}

