use crate::f512_569::F512_569;

pub fn eval_lagrange(ys: &[F512_569], i: usize, x: &F512_569) -> F512_569 {
    assert!(i < ys.len());

    let y = ys[i];
    ys[..i]
        .iter()
        .chain(ys[(i + 1)..].iter())
        .map(|z| &(x - z) * &(&y - &z).recip())
        .product()
}

#[cfg(test)]
mod test {
    use super::*;
    use core::iter::once;
    use quickcheck::quickcheck;
    use subtle::ConstantTimeEq;

    #[quickcheck]
    fn lagrange_eval_correct(
        pref: Vec<F512_569>,
        y: F512_569,
        suff: Vec<F512_569>,
        i: /*Vec<*/ u8, /*>*/
    ) {
        let mut proper_ys = vec![];
        for v in pref {
            if !once(&y)
                .chain(proper_ys.iter())
                .any(|x| bool::from(v.ct_eq(x)))
            {
                proper_ys.push(v);
            }
        }
        let y_ix = proper_ys.len();
        proper_ys.push(y);
        for v in suff {
            if !proper_ys.iter().any(|x| bool::from(v.ct_eq(x))) {
                proper_ys.push(v);
            }
        }
        let ys = proper_ys;

        // for i in is {
        let i = (i as usize) % ys.len();

        let res = eval_lagrange(&ys, y_ix, &ys[i]);
        if i == y_ix {
            assert!(bool::from(res.ct_eq(&F512_569::one())));
        } else {
            assert!(bool::from(res.ct_eq(&F512_569::zero())));
        }
        // }
    }
}
