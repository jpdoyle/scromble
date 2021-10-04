use crate::f512_569::F512_569;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub fn eval_lagrange(ys: &[F512_569], i: usize, x: &F512_569) -> F512_569 {
    assert!(i < ys.len());

    let y = ys[i];
    let denom: F512_569 = ys[..i]
        .iter()
        .chain(ys[(i + 1)..].iter())
        .map(|z| &y - &z)
        .product();
    let numer: F512_569 = ys[..i]
        .iter()
        .chain(ys[(i + 1)..].iter())
        .map(|z| x - z)
        .product();
    &numer * &denom.recip()
}

#[derive(Debug, Clone)]
pub struct SecretShare(F512_569);

fn ct_contains<'a>(
    arr: impl Iterator<Item = &'a F512_569>,
    x: &F512_569,
) -> Choice {
    let mut ret = Choice::from(0);
    for y in arr {
        ret |= x.ct_eq(y);
    }
    ret
}

pub fn share_secret(
    secret: F512_569,
    blinding_coeffs: &[F512_569],
    share_points: &[F512_569],
) -> Option<Vec<SecretShare>> {
    if bool::from(ct_contains(share_points.iter(), &F512_569::zero())) {
        return None;
    }

    let num_unique_share_points = {
        let mut ret = 0u32;
        for i in 0..share_points.len() {
            ret += u32::conditional_select(
                &1,
                &0,
                ct_contains(
                    share_points[i + 1..].iter(),
                    &share_points[i],
                ),
            );
        }
        ret as usize
    };

    if num_unique_share_points < blinding_coeffs.len() + 1 {
        return None;
    }

    let mut ret = vec![];
    for x in share_points {
        let mut y = secret;
        let mut term = *x;

        for coeff in blinding_coeffs {
            y += &(coeff * &term);
            term *= x;
        }
        ret.push(y);
    }

    Some(ret.into_iter().map(SecretShare).collect())
}

pub fn reconstruct_secret(shares: &[(F512_569, SecretShare)]) -> F512_569 {
    let mut ret = F512_569::zero();

    let xs = shares.iter().map(|(x, _y)| *x).collect::<Vec<_>>();

    for (i, coeff) in shares.iter().map(|(_x, y)| y).enumerate() {
        ret += &(&coeff.0 * &eval_lagrange(&xs, i, &F512_569::zero()));
    }

    ret
}

#[cfg(test)]
mod test {
    use super::*;
    use core::iter::once;
    use quickcheck::quickcheck;
    use subtle::ConditionallySelectable;

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
            if !bool::from(ct_contains(proper_ys.iter(), &v)) {
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

    #[quickcheck]
    fn secret_sharing_reconstructs(
        which_shares: Vec<usize>,
        mut blinds: Vec<F512_569>,
        xs: (Vec<F512_569>, F512_569),

        secret: F512_569,
        fake_secret: F512_569,
    ) {
        let xs = (xs.1, xs.0);
        // println!(
        //     "secret_sharing_reconstructs: {} blinds, {} shares, {} chosen shares",
        //     blinds.len(),
        //     1 + (xs.1).len(),
        //     which_shares.len()
        // );
        let xs: Vec<_> = once(xs.0)
            .chain((xs.1).into_iter())
            .map(|x| {
                F512_569::conditional_select(
                    &x,
                    &F512_569::one(),
                    x.ct_eq(&F512_569::zero()),
                )
            })
            .collect();

        let mut shares;

        while {
            shares = share_secret(secret.clone(), &blinds, &xs);
            shares.is_none()
        } {
            blinds.pop().unwrap();
        }

        let shares = shares.unwrap();
        // dbg!(shares.len());
        // dbg!(blinds.len());

        assert_eq!(xs.len(), shares.len());

        let mut which_shares = {
            let mut ret = vec![];
            let mut ret_xs = vec![];
            for s in which_shares {
                let s = s % shares.len();
                if !ret.contains(&s) {
                    let s_x = xs[s].clone();
                    if !bool::from(ct_contains(ret_xs.iter(), &s_x)) {
                        ret.push(s);
                        ret_xs.push(s_x);
                    }
                }
            }

            let mut last_val = ret.last().cloned().unwrap_or(0);
            while ret.len() < blinds.len() + 1 {
                last_val = (last_val + 1) % shares.len();
                let s = last_val;
                if !ret.contains(&s) {
                    let s_x = xs[s].clone();

                    if !bool::from(ct_contains(ret_xs.iter(), &s_x)) {
                        ret.push(s);
                        ret_xs.push(s_x);
                    }
                }
            }

            ret
        };

        // Whenever we have more shares than blinds, we reconstruct the
        // right secret
        let mut last_ix = 0;
        while which_shares.len() > blinds.len() {
            // println!(
            //     "secret_sharing_reconstructs: {} shares remaining",
            //     which_shares.len()
            // );
            assert!(bool::from(
                reconstruct_secret(
                    &which_shares
                        .iter()
                        .cloned()
                        .map(|i| (xs[i], shares[i].clone()))
                        .collect::<Vec<_>>()
                )
                .ct_eq(&secret)
            ));

            last_ix = which_shares.pop().unwrap();
        }

        // But with even one less, we can add fake shares that construct an
        // arbitrary other secret
        which_shares.push(last_ix);
        let fake_shares = {
            let orig_x = xs[last_ix];
            let fake_points: Vec<_> = which_shares
                .iter()
                .cloned()
                .map(|i| (xs[i], shares[i].clone()))
                .map(|(x, y)| {
                    (
                        F512_569::conditional_select(
                            &x,
                            &F512_569::zero(),
                            x.ct_eq(&orig_x),
                        ),
                        SecretShare(F512_569::conditional_select(
                            &y.0,
                            &fake_secret,
                            x.ct_eq(&orig_x),
                        )),
                    )
                })
                .collect();

            let fake_xs: Vec<_> =
                fake_points.iter().map(|(x, _y)| x.clone()).collect();

            let fake_share = fake_points
                .iter()
                .enumerate()
                .map(|(i, (_, coeff))| {
                    &coeff.0 * &eval_lagrange(&fake_xs, i, &orig_x)
                })
                .sum();

            let ret: Vec<_> = xs
                .iter()
                .zip(shares.iter())
                .map(|(x, y)| {
                    SecretShare(F512_569::conditional_select(
                        &y.0,
                        &fake_share,
                        x.ct_eq(&orig_x),
                    ))
                })
                .collect();

            ret
        };

        assert!(bool::from(
            reconstruct_secret(
                &which_shares
                    .iter()
                    .cloned()
                    .map(|i| (xs[i], fake_shares[i].clone()))
                    .collect::<Vec<_>>()
            )
            .ct_eq(&fake_secret)
        ));
    }
}
