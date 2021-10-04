#![deny(warnings)]
#![allow(clippy::suspicious_op_assign_impl)]
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
#[cfg(test)]
use quickcheck::{Arbitrary, Gen};
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, Default, Zeroize)]
pub struct F512_569([u64; 8]);

fn adc(x: u64, y: u64, c: u64) -> (u64, u64) {
    let ret: u128 = (x as u128) + (y as u128) + (c as u128);
    ((ret & ((1u128 << 64) - 1)) as u64, (ret >> 64) as u64)
}

// calculate (lo,hi) such that x*y + a + c == hi*2^64 + lo
//
// Won't overflow because (2^64 - 1)^2 = (2^128 - 1) - 2*(2^64 - 1)
fn mac(x: u64, y: u64, a: u64, c: u64) -> (u64, u64) {
    let ret: u128 =
        ((x as u128) * (y as u128)) + (a as u128) + (c as u128);
    ((ret & ((1u128 << 64) - 1)) as u64, (ret >> 64) as u64)
}

impl<'b> AddAssign<&'b F512_569> for F512_569 {
    fn add_assign(&mut self, other: &'b F512_569) {
        let mut carry = 0;

        for i in 0..8 {
            let (res, next_carry) = adc(self.0[i], other.0[i], carry);
            self.0[i] = res;
            carry = next_carry;
        }

        carry *= 569;

        for i in 0..8 {
            let (res, next_carry) = adc(self.0[i], 0, carry);
            self.0[i] = res;
            carry = next_carry;
        }

        self.reduce();
    }
}

impl F512_569 {
    pub fn zero() -> Self {
        Self::from_u64(0)
    }

    pub fn one() -> Self {
        Self::from_u64(1)
    }

    pub fn random<R: Rng + CryptoRng>(prng: &mut R) -> Self {
        let mut ret = Self(prng.gen());
        ret.reduce();
        ret
    }

    pub fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0, 0, 0, 0, 0])
    }

    fn negate(&mut self) {
        // first, add 568 (if we're reduced, this will not overflow)

        let (l0, mut carry) = adc(self.0[0], 568, 0);
        self.0[0] = l0;

        for i in 1..8 {
            let (res, next_carry) = adc(self.0[i], 0, carry);
            self.0[i] = res;
            carry = next_carry;
        }

        debug_assert_eq!(carry, 0);
        debug_assert_eq!(u64::MAX as u128, (1u128 << 64) - 1);

        // x + 568 -> (2^512 - 1) - (x + 568)
        for i in 0..8 {
            self.0[i] = u64::MAX - self.0[i];
        }

        self.reduce();
    }

    // variable time in the exponent
    pub fn pow_vartime(&self, exponent: &[u64]) -> Self {
        let mut pow2 = *self;
        let mut ret = Self::one();

        for limb in exponent {
            for shift in 0..64 {
                if ((limb >> shift) & 1) != 0 {
                    ret *= &pow2;
                }
                pow2 *= &pow2.clone();
            }
        }
        ret
    }

    pub fn recip(&self) -> Self {
        // x^-1 == x^((2^512 - 569) - 2)
        //      == x^((2^512 - 1) - 570)
        self.pow_vartime(&[
            u64::MAX - 570, // 0
            u64::MAX,       // 1
            u64::MAX,       // 2
            u64::MAX,       // 3
            u64::MAX,       // 4
            u64::MAX,       // 5
            u64::MAX,       // 6
            u64::MAX,       // 7
        ])
    }
}

impl<'a, 'b> Add<&'b F512_569> for &'a F512_569 {
    type Output = F512_569;
    fn add(self, b: &'b F512_569) -> F512_569 {
        let mut ret = *self;
        ret += b;
        ret
    }
}

impl<'a> Neg for &'a F512_569 {
    type Output = F512_569;
    fn neg(self) -> F512_569 {
        let mut ret = *self;
        ret.negate();
        ret
    }
}

impl<'b> SubAssign<&'b F512_569> for F512_569 {
    fn sub_assign(&mut self, other: &'b F512_569) {
        *self += &other.neg();
    }
}

impl<'a, 'b> Sub<&'b F512_569> for &'a F512_569 {
    type Output = F512_569;
    fn sub(self, b: &'b F512_569) -> F512_569 {
        let mut ret = *self;
        ret -= b;
        ret
    }
}

impl<'a, 'b> Mul<&'b F512_569> for &'a F512_569 {
    type Output = F512_569;
    fn mul(self, rhs: &'b F512_569) -> F512_569 {
        let mut res = [0u64; 2 * 8];

        for i in 0..8 {
            let mut carry = 0;
            for j in 0..8 {
                let ix = i + j;
                let (val, next_carry) =
                    mac(self.0[i], rhs.0[j], res[ix], carry);
                res[ix] = val;
                carry = next_carry;
            }

            for r in res[(i + 8)..16].iter_mut() {
                let (val, next_carry) = adc(*r, 0, carry);
                *r = val;
                carry = next_carry;
            }
            debug_assert_eq!(carry, 0);
        }

        {
            let mut carry = 0;
            for i in 0..8 {
                let over = res[i + 8];
                res[i + 8] = 0;

                let (val, next_carry) = mac(over, 569, res[i], carry);
                res[i] = val;
                carry = next_carry;
            }
            res[8] = carry;
        }

        {
            let over = res[8];
            res[8] = 0;
            let (v0, mut carry) = mac(over, 569, res[0], 0);
            res[0] = v0;

            for r in res[1..8].iter_mut() {
                let (val, next_carry) = adc(*r, 0, carry);
                *r = val;
                carry = next_carry;
            }
            // if i == 1 {
            debug_assert_eq!(carry, 0);
            // }
        }

        for r in &res[8..16] {
            debug_assert_eq!(*r, 0);
        }

        let mut ret = F512_569([
            res[0], res[1], res[2], res[3], res[4], res[5], res[6], res[7],
        ]);
        ret.reduce();

        ret
    }
}

impl Sum<F512_569> for F512_569 {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = F512_569>,
    {
        let mut ret = Self::zero();
        for x in iter {
            ret += &x;
        }
        ret
    }
}

impl Product<F512_569> for F512_569 {
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = F512_569>,
    {
        let mut ret = Self::one();
        for x in iter {
            ret *= &x;
        }
        ret
    }
}

impl<'b> MulAssign<&'b F512_569> for F512_569 {
    fn mul_assign(&mut self, rhs: &'b F512_569) {
        self.0 = ((self as &F512_569) * rhs).0;
    }
}

impl ConditionallySelectable for F512_569 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut ret = Self([0; 8]);
        for i in 0..8 {
            ret.0[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
        }
        ret
    }
}

impl ConstantTimeEq for F512_569 {
    fn ct_eq(&self, b: &Self) -> Choice {
        let mut ret = Choice::from(1);
        for (x, y) in self.0.iter().zip(b.0.iter()) {
            ret &= x.ct_eq(y);
        }
        ret
    }
}

impl F512_569 {
    /// Reduce to be less that 2^512 - 569
    ///
    /// given `x`, calculates `y = x + 569 mod 2^512`, then replaces `x`
    /// with `y` if and only if `y` overflowed.
    fn reduce(&mut self) {
        let mut y = Self([0u64; 8]);
        let (l0, mut carry) = adc(self.0[0], 569, 0);
        y.0[0] = l0;

        for i in 1..8 {
            let (next, carr) = adc(self.0[i], 0, carry);
            y.0[i] = next;
            carry = carr;
        }

        let swap = Choice::from((carry & 0xff) as u8);
        *self = Self::conditional_select(&self, &y, swap);
    }
}

impl From<&F512_569> for [u8; 64] {
    fn from(v: &F512_569) -> [u8; 64] {
        let mut ret = [0; 64];
        for i in 0..8 {
            for j in 0..8 {
                ret[8 * i + j] = ((v.0[i] >> (8 * j)) & 0xff) as u8;
            }
        }

        ret
    }
}

impl From<&[u8; 64]> for F512_569 {
    fn from(arr: &[u8; 64]) -> F512_569 {
        let mut ret = F512_569([0; 8]);
        for i in 0..8 {
            for j in 0..8 {
                ret.0[i] |= (arr[8 * i + j] as u64) << (8 * j);
            }
        }

        ret.reduce();
        ret
    }
}

#[cfg(test)]
impl Arbitrary for F512_569 {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut ret = Self::zero();
        for limb in ret.0.iter_mut() {
            *limb = u64::arbitrary(g);
        }
        ret.reduce();
        ret
    }

    fn shrink(&self) -> Box<(dyn Iterator<Item = Self> + 'static)> {
        let mut my_vec = self.0.to_vec();
        while my_vec.last() == Some(&0) {
            my_vec.pop().unwrap();
        }
        Box::new(my_vec.shrink().map(|v| {
            let mut ret = Self::zero();
            let len = core::cmp::min(v.len(), ret.0.len());
            ret.0[..len].copy_from_slice(&v);
            ret.reduce();
            ret
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num::Integer;
    use num::{bigint::Sign, BigInt};
    use quickcheck::quickcheck;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;

    lazy_static! {
        static ref P512_569: BigInt =
            BigInt::from(2).pow(512) - BigInt::from(569);
    }

    // A Pratt certificate for `p` is a proof that there is some value
    // 2 < g < p such that:
    //  - g^(p-1) == 1 mod p
    //  - for each prime factor q of `p-1`, `g^((p-1)/q) != 1 mod p`
    // This proves that g's order mod p is `p-1`, which is only possible if
    // `p` is prime. (since if q|p, q|(q^(p-1) mod p), but also for some r,
    // q = g^r mod p, so
    // q^(p-1) = (g^r)^(p-1) = (g^(p-1))^r = 1^r = 1 mod p
    // and thus q|1).
    //
    // The prime factors q recursively have their own certificates, until
    // they are less than `1000^2`, at which point exhaustive checking up
    // to `~sqrt(q)` is done.
    enum PrattCert {
        Small,
        Cert {
            generator: BigInt,
            factorization: Vec<(BigInt, u32, PrattCert)>,
        },
    }

    fn check_pratt_cert(p: BigInt, cert: PrattCert) -> Result<(), ()> {
        match cert {
            PrattCert::Small => {
                if BigInt::from(1000).pow(2) < p {
                    return Err(());
                }
                let mut ret = Ok(());
                for i in 2..=1000 {
                    let i = BigInt::from(i);
                    if i.pow(2) > p {
                        break;
                    }
                    if p.clone() % i == BigInt::from(0) {
                        ret = Err(());
                        break;
                    }
                }
                ret
            }

            PrattCert::Cert {
                generator,
                factorization,
            } => {
                let fact_prod = factorization
                    .iter()
                    .map(|(q, e, _)| q.pow(*e))
                    .product::<BigInt>();

                let p_1 = p.clone() - BigInt::from(1);

                if fact_prod != p_1 {
                    return Err(());
                }

                if generator.modpow(&p_1, &p) != BigInt::from(1) {
                    return Err(());
                }

                for (q, _, cert) in factorization {
                    check_pratt_cert(q.clone(), cert)?;

                    let quot = (p_1).checked_div(&q).unwrap();
                    if generator.modpow(&quot, &p) == BigInt::from(1) {
                        return Err(());
                    }
                }

                Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    fn to_from_F512_569(v: Vec<u8>) {
        let arr: [u8; 64] = {
            let mut ret = [0; 64];
            for (i, x) in v.into_iter().enumerate() {
                if i >= 64 {
                    break;
                }
                ret[i] = x;
            }
            ret
        };
        {
            let f = F512_569::from(&arr);
            let arr2 = <[u8; 64]>::from(&f);
            let f2 = F512_569::from(&arr2);
            assert_eq!(<[u8; 64]>::from(&f2), arr2);
            let bi_arr =
                BigInt::from_radix_le(Sign::Plus, &arr, 256).unwrap();
            let bi_arr2 =
                BigInt::from_radix_le(Sign::Plus, &arr2, 256).unwrap();
            assert_eq!(bi_arr % P512_569.clone(), bi_arr2);
        }
        {
            let mut arr_no_wrap = arr.clone();
            arr_no_wrap[0] &= !((569u32 & 0xff) as u8);
            arr_no_wrap[1] &= !(((569u32 >> 8) & 0xff) as u8);
            let f = F512_569::from(&arr_no_wrap);
            assert_eq!(<[u8; 64]>::from(&f), arr_no_wrap);
        }
    }

    #[test]
    fn edge_cases_to_from_f512_569() {
        to_from_F512_569(vec![0]);
        for i in 0..=569u16 {
            let mut arr = vec![0xff; 64];
            let b1 = (i & 0xff) as u8;
            let b2 = (i >> 8) as u8;
            arr[0] -= b1;
            arr[1] -= b2;
            to_from_F512_569(arr);
        }
    }

    #[test]
    fn quickcheck_to_from_f512_569() {
        quickcheck(to_from_F512_569 as fn(_) -> ());
    }

    #[derive(Debug, Clone)]
    enum FieldOp {
        Neg,
        Add,
        Sub,
        Mul,
        Recip,
        Pow,
        PseudoRandom,
    }

    impl Arbitrary for FieldOp {
        fn arbitrary(g: &mut Gen) -> Self {
            use FieldOp::*;
            g.choose(&[Neg, Add, Sub, Mul, Recip, Pow, PseudoRandom])
                .unwrap()
                .clone()
        }
    }

    #[quickcheck]
    fn stack_eval_test(
        default_val: F512_569,
        program: Vec<Result<F512_569, FieldOp>>,
    ) {
        let field_val = {
            let mut stack = vec![];
            for x in program.iter().cloned() {
                match x {
                    Ok(val) => {
                        stack.push(val);
                    }

                    Err(op) => {
                        use FieldOp::*;
                        match op {
                            Neg => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(-&val);
                            }
                            Add => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(&l + &r);
                            }
                            Sub => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(&l - &r);
                            }
                            Mul => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(&l * &r);
                            }
                            Recip => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let recip = val.recip();
                                stack.push(recip);

                                if bool::from(val.ct_eq(&F512_569::zero()))
                                {
                                    // dbg!(&val);
                                    // dbg!(&recip);
                                    assert!(bool::from(
                                        recip.ct_eq(&F512_569::zero())
                                    ));
                                } else {
                                    assert!(bool::from(
                                        (&val * &recip)
                                            .ct_eq(&F512_569::one())
                                    ));
                                }
                            }
                            Pow => {
                                let e = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let b = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(b.pow_vartime(&e.0));
                            }

                            PseudoRandom => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let mut hasher = DefaultHasher::new();
                                for limb in &val.0 {
                                    // dbg!(&limb);
                                    hasher.write_u64(*limb);
                                }
                                let mut new_val = [0u8; 64];
                                for i in 0..8 {
                                    let chunk = hasher.finish();
                                    hasher.write_u64(0);
                                    for j in 0..8 {
                                        new_val[8 * i + j] =
                                            ((chunk >> (8 * j)) & 0xff)
                                                as u8;
                                    }
                                }
                                // dbg!(&new_val);
                                stack.push(F512_569::from(&new_val));
                            }
                        }
                    }
                }
            }

            stack
        };

        let bigint_val = {
            let mut stack = vec![];
            let p = P512_569.clone();
            let default_val = BigInt::from_bytes_le(
                Sign::Plus,
                &<[u8; 64]>::from(&default_val),
            );
            for x in program {
                match x {
                    Ok(val) => {
                        stack.push(BigInt::from_bytes_le(
                            Sign::Plus,
                            &<[u8; 64]>::from(&val),
                        ));
                    }

                    Err(op) => {
                        use FieldOp::*;
                        match op {
                            Neg => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push((-val).mod_floor(&p));
                            }
                            Add => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push((l + r).mod_floor(&p));
                            }
                            Sub => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push((l - r).mod_floor(&p));
                            }
                            Mul => {
                                let r = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let l = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push((l * r).mod_floor(&p));
                            }
                            Recip => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(val.modpow(&(&p - 2), &p));
                            }
                            Pow => {
                                let e = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let b = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                stack.push(b.modpow(&e, &p));
                            }

                            PseudoRandom => {
                                let val = stack
                                    .pop()
                                    .unwrap_or(default_val.clone());
                                let mut hasher = DefaultHasher::new();
                                let limbs = {
                                    let mut ret = [0u64; 8];
                                    let u64_digits = val.to_u64_digits().1;
                                    ret[..u64_digits.len()]
                                        .copy_from_slice(&u64_digits);
                                    ret
                                };
                                for limb in &limbs {
                                    // dbg!(&limb);
                                    hasher.write_u64(*limb);
                                }
                                let mut new_val = [0u8; 64];
                                for i in 0..8 {
                                    let chunk = hasher.finish();
                                    hasher.write_u64(0);
                                    for j in 0..8 {
                                        new_val[8 * i + j] =
                                            ((chunk >> (8 * j)) & 0xff)
                                                as u8;
                                    }
                                }
                                // dbg!(&new_val);
                                stack.push(
                                    BigInt::from_bytes_le(
                                        Sign::Plus,
                                        &new_val,
                                    )
                                    .mod_floor(&p),
                                );
                            }
                        }
                    }
                }
            }

            stack
        };

        assert_eq!(
            field_val
                .into_iter()
                .map(|x| <[u8; 64]>::from(&x))
                .collect::<Vec<_>>(),
            bigint_val
                .into_iter()
                .map(|x| {
                    let mut ret = [0u8; 64];
                    let x_bytes = x.to_bytes_le().1;
                    ret[..x_bytes.len()].copy_from_slice(&x_bytes);
                    ret
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn prime_2_512_569() {
        use PrattCert::*;
        let pb = |x| BigInt::parse_bytes(x, 10).unwrap();
        check_pratt_cert(
            P512_569.clone(),
            Cert {
                factorization: vec![
                    (pb(b"2"), 1, Small),
                    (pb(b"23"), 1, Small),
                    (pb(b"41"), 1, Small),
                    (pb(b"353"), 1, Small),
                    (
                        pb(b"105095387"),
                        1,
                        Cert {
                            factorization: vec![
                                (pb(b"2"), 1, Small),
                                (pb(b"11"), 1, Small),
                                (
                                    pb(b"4777063"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (pb(b"3"), 1, Small),
                                            (
                                                pb(b"796177"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 4, Small),
                                                        (pb(b"3"), 3, Small),
                                                        (pb(b"19"), 1, Small),
                                                        (pb(b"97"), 1, Small),
                                                    ],
                                                    generator: pb(b"13"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"5"),
                                    },
                                ),
                            ],
                            generator: pb(b"2"),
                        },
                    ),
                    (
                        pb(b"45130584520747958722981"),
                        1,
                        Cert {
                            factorization: vec![
                                (pb(b"2"), 2, Small),
                                (pb(b"3"), 1, Small),
                                (pb(b"5"), 1, Small),
                                (pb(b"7"), 1, Small),
                                (pb(b"71"), 1, Small),
                                (pb(b"12653"), 1, Small),
                                (
                                    pb(b"119610639205363"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (pb(b"3"), 2, Small),
                                            (pb(b"31"), 2, Small),
                                            (pb(b"24317"), 1, Small),
                                            (pb(b"284357"), 1, Small),
                                        ],
                                        generator: pb(b"2"),
                                    },
                                ),
                            ],
                            generator: pb(b"11"),
                        },
                    ),
                    (
                        pb(b"582271299047893027187874292913927407"),
                        1,
                        Cert {
                            factorization: vec![
                                (pb(b"2"), 1, Small),
                                (pb(b"3"), 1, Small),
                                (pb(b"277"), 1, Small),
                                (
                                    pb(b"350343741906072820209310645555913"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 3, Small),
                                            (
                                                pb(b"522744931663"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 1, Small),
                                                        (pb(b"3"), 1, Small),
                                                        (pb(b"41"), 1, Small),
                                                        (pb(b"89"), 1, Small),
                                                        (pb(b"421"), 1, Small),
                                                        (pb(b"56713"), 1, Small),
                                                    ],
                                                    generator: pb(b"3"),
                                                },
                                            ),
                                            (
                                                pb(b"83775021211475436503"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 1, Small),
                                                        (pb(b"11"), 1, Small),
                                                        (pb(b"653"), 1, Small),
                                                        (
                                                            pb(b"564643"),
                                                            1,
                                                            Cert {
                                                                factorization: vec![
                                                                    (pb(b"2"), 1, Small),
                                                                    (pb(b"3"), 2, Small),
                                                                    (pb(b"13"), 1, Small),
                                                                    (pb(b"19"), 1, Small),
                                                                    (pb(b"127"), 1, Small),
                                                                ],
                                                                generator: pb(b"5"),
                                                            },
                                                        ),
                                                        (
                                                            pb(b"10327726679"),
                                                            1,
                                                            Cert {
                                                                factorization: vec![
                                                                    (pb(b"2"), 1, Small),
                                                                    (pb(b"17"), 1, Small),
                                                                    (pb(b"19"), 1, Small),
                                                                    (pb(b"569"), 1, Small),
                                                                    (pb(b"28097"), 1, Small),
                                                                ],
                                                                generator: pb(b"7"),
                                                            },
                                                        ),
                                                    ],
                                                    generator: pb(b"5"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"3"),
                                    },
                                ),
                            ],
                            generator: pb(b"3"),
                        },
                    ),
                    (
                        pb(b"2440563294432588452310063876982204011061"),
                        1,
                        Cert {
                            factorization: vec![
                                (pb(b"2"), 2, Small),
                                (pb(b"3"), 1, Small),
                                (pb(b"5"), 1, Small),
                                (pb(b"6827"), 1, Small),
                                (pb(b"19571"), 1, Small),
                                (pb(b"64231"), 1, Small),
                                (
                                    pb(b"18992539"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (pb(b"3"), 2, Small),
                                            (
                                                pb(b"1055141"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 2, Small),
                                                        (pb(b"5"), 1, Small),
                                                        (pb(b"52757"), 1, Small),
                                                    ],
                                                    generator: pb(b"2"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"2"),
                                    },
                                ),
                                (
                                    pb(b"377723741"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 2, Small),
                                            (pb(b"5"), 1, Small),
                                            (pb(b"367"), 1, Small),
                                            (pb(b"51461"), 1, Small),
                                        ],
                                        generator: pb(b"3"),
                                    },
                                ),
                                (
                                    pb(b"660684187"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (pb(b"3"), 2, Small),
                                            (pb(b"67"), 1, Small),
                                            (
                                                pb(b"547831"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 1, Small),
                                                        (pb(b"3"), 3, Small),
                                                        (pb(b"5"), 1, Small),
                                                        (pb(b"2029"), 1, Small),
                                                    ],
                                                    generator: pb(b"3"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"2"),
                                    },
                                ),
                            ],
                            generator: pb(b"2"),
                        },
                    ),
                    (
                        pb(b"2987936166061269764733822017919288608395313"),
                        1,
                        Cert {
                            factorization: vec![
                                (pb(b"2"), 4, Small),
                                (pb(b"19"), 1, Small),
                                (pb(b"503"), 1, Small),
                                (pb(b"10163"), 1, Small),
                                (
                                    pb(b"42853043"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (
                                                pb(b"21426521"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 3, Small),
                                                        (pb(b"5"), 1, Small),
                                                        (
                                                            pb(b"535663"),
                                                            1,
                                                            Cert {
                                                                factorization: vec![
                                                                    (pb(b"2"), 1, Small),
                                                                    (pb(b"3"), 2, Small),
                                                                    (pb(b"29759"), 1, Small),
                                                                ],
                                                                generator: pb(b"3"),
                                                            },
                                                        ),
                                                    ],
                                                    generator: pb(b"17"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"2"),
                                    },
                                ),
                                (
                                    pb(b"518580685877"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 2, Small),
                                            (pb(b"11"), 1, Small),
                                            (pb(b"17"), 1, Small),
                                            (pb(b"73"), 1, Small),
                                            (pb(b"1087"), 1, Small),
                                            (pb(b"8737"), 1, Small),
                                        ],
                                        generator: pb(b"2"),
                                    },
                                ),
                                (
                                    pb(b"86518666347907"),
                                    1,
                                    Cert {
                                        factorization: vec![
                                            (pb(b"2"), 1, Small),
                                            (pb(b"3"), 1, Small),
                                            (pb(b"13"), 1, Small),
                                            (pb(b"168601"), 1, Small),
                                            (
                                                pb(b"6578927"),
                                                1,
                                                Cert {
                                                    factorization: vec![
                                                        (pb(b"2"), 1, Small),
                                                        (
                                                            pb(b"3289463"),
                                                            1,
                                                            Cert {
                                                                factorization: vec![
                                                                    (pb(b"2"), 1, Small),
                                                                    (pb(b"11"), 1, Small),
                                                                    (pb(b"149521"), 1, Small),
                                                                ],
                                                                generator: pb(b"5"),
                                                            },
                                                        ),
                                                    ],
                                                    generator: pb(b"5"),
                                                },
                                            ),
                                        ],
                                        generator: pb(b"5"),
                                    },
                                ),
                            ],
                            generator: pb(b"3"),
                        },
                    ),
                ],
                generator: pb(b"7"),
            },
        )
        .unwrap()
    }
}
