
#[derive(Debug,Clone,Default)]
struct F512_569([u64; 10]);

impl F512_569 {

    /// Reduce the limbs to be <2^51, except:
    ///  - the last limb will be <2^53
    ///  - the first limb may be between 2^51 and 2^53.
    /// Assumes that all limbs are below 2^63.
    fn reduce(&mut self) {
        for i in 0..9 {
            let carry = self.0[i]>>51;
            self.0[i+1] += carry;
            self.0[i] &= (1<<51)-1;
        }
        let final_carry = self.0[9]>>53;
        self.0[9] &= (1<<53)-1;
        self.0[0] += final_carry*569;
    }

    /// Fully reduce the limbs to be <2^51, except the last limb, which is
    /// <2^53.
    /// Assumes that all limbs are below 2^63.
    fn reduce_full(&mut self) {
        self.reduce();
        // Now all but the first limb are in reduced form, and there's at
        // most 1 carry bit in the first limb.
        self.reduce();

        // If all limbs above the first were at their maximum value, we may
        // have one more carry bit in the first limb.
        //
        // But in that case, and we know that the second limb is now zero.
        self.0[1] += 569*(self.0[0]>>51);
        self.0[0] &= (1<<51)-1;

        for i in 0..9 {
            debug_assert!(self.0[i] < 1<<51);
        }
        debug_assert!(self.0[9] < 1<<53);
    }
}

impl From<&F512_569> for [u8;64] {
    fn from(v: &F512_569) -> [u8;64] {
        let mut ret = [0;64];
        let mut v = v.clone();
        v.reduce_full();

        let mut out_ix = 0;
        let mut bits_avail = 0;
        let mut curr = 0;
        for i in 0..10 {
            curr |= v.0[i]<<bits_avail;
            bits_avail += if i == 9 { 53 } else { 51 };
            while bits_avail >= 8 {
                ret[out_ix] = (curr&0xff) as u8;
                out_ix += 1;
                curr >>= 8;
                bits_avail -= 8;
            }
        }
        debug_assert_eq!(bits_avail,0);
        debug_assert_eq!(out_ix,64);
        debug_assert_eq!(curr,0);
        ret
    }
}

impl From<&[u8;64]> for F512_569 {
    fn from(arr: &[u8;64]) -> F512_569 {
        let mut ret = F512_569([0;10]);

        let mut in_ix = 0;
        let mut shift = 0;
        for i in 0..10 {
            while in_ix < 64 && shift < 64-8 {
                ret.0[i] |= (arr[in_ix] as u64)<<shift;
                shift += 8;
                in_ix += 1;
            }
            shift -= if i == 9 { 53 } else { 51 };
        }

        ret.reduce();
        ret
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use quickcheck::quickcheck;
    use num::BigInt;

    enum PrattCert {
        Small,
        Cert {
            generator: BigInt,
            factorization: Vec<(BigInt,u32,PrattCert)>,
        },
    }

    fn check_pratt_cert(p: BigInt, cert: PrattCert) -> Result<(),()> {
        match cert {
            PrattCert::Small => {
                let mut ret = Ok(());
                for i in 2..1000 {
                    let i = BigInt::from(i);
                    if i.pow(2) > p {
                        break;
                    }
                    if p.clone()%i == BigInt::from(0) {
                        ret = Err(());
                        break;
                    }
                }
                ret
            },

            PrattCert::Cert { generator, factorization } => {
                let fact_prod = factorization.iter()
                                             .map(|(q,e,_)| q.pow(*e))
                                             .product::<BigInt>();

                let p_1 = p.clone() - BigInt::from(1);

                if fact_prod != p_1 {
                    return Err(());
                }

                if generator.modpow(&p_1,&p) != BigInt::from(1) {
                    return Err(());
                }

                for (q,_,cert) in factorization {
                    check_pratt_cert(q.clone(),cert)?;

                    let quot = (p_1).checked_div(&q).unwrap();
                    if generator.modpow(&quot,&p) == BigInt::from(1) {
                        return Err(());
                    }
                }

                Ok(())
            }
        }
    }

    #[allow(non_snake_case)]
    fn to_from_F512_569(v: Vec<u8>) {
        let arr: [u8;64] = {
            let mut ret = [0;64];
            for (i,x) in v.into_iter().enumerate() {
                if i >= 64 {
                    break;
                }
                ret[i] = x;
            }
            ret
        };
        {
            let f = F512_569::from(&arr);
            let arr2 = <[u8;64]>::from(&f);
            let f2 = F512_569::from(&arr2);
            assert_eq!(<[u8;64]>::from(&f2),arr2);
        }
        {
            let mut arr_no_wrap = arr.clone();
            arr_no_wrap[63] >>= 2;
            let f = F512_569::from(&arr_no_wrap);
            assert_eq!(<[u8;64]>::from(&f),arr_no_wrap);
        }
    }

    #[test]
    fn quickcheck_to_from_f512_569() {
        quickcheck(to_from_F512_569 as fn(_) -> ());
    }

    #[test]
    fn prime_2_512_569() {
        use PrattCert::*;
        let pb = |x| BigInt::parse_bytes(x,10).unwrap();
        check_pratt_cert(
            BigInt::from(2).pow(512)-BigInt::from(569),

	    Cert {
		factorization: vec![
		    (pb(b"2"), 1, Small),
		    (pb(b"23"), 1, Small),
		    (pb(b"41"), 1, Small),
		    (pb(b"353"), 1, Small),
		    (pb(b"105095387"), 1,
		     Cert {
			 factorization: vec![
			     (pb(b"2"), 1, Small),
			     (pb(b"11"), 1, Small),
			     (pb(b"4777063"), 1,
			      Cert {
				  factorization: vec![
				      (pb(b"2"), 1, Small),
				      (pb(b"3"), 1, Small),
				      (pb(b"796177"), 1,
				       Cert {
					   factorization: vec![
					       (pb(b"2"), 4, Small),
					       (pb(b"3"), 3, Small),
					       (pb(b"19"), 1, Small),
					       (pb(b"97"), 1, Small) ],
					       generator: pb(b"13")
				       }
				      ) ],
				      generator: pb(b"5")
			      }
			     ) ],
			     generator: pb(b"2")
		     }
		),
		(pb(b"45130584520747958722981"), 1,
		 Cert {
		     factorization: vec![
			 (pb(b"2"), 2, Small),
			 (pb(b"3"), 1, Small),
			 (pb(b"5"), 1, Small),
			 (pb(b"7"), 1, Small),
			 (pb(b"71"), 1, Small),
			 (pb(b"12653"), 1, Small),
			 (pb(b"119610639205363"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 1, Small),
				  (pb(b"3"), 2, Small),
				  (pb(b"31"), 2, Small),
				  (pb(b"24317"), 1, Small),
				  (pb(b"284357"), 1, Small) ],
				  generator: pb(b"2")
			  }
			 ) ],
			 generator: pb(b"11")
		 }
		),
		(pb(b"582271299047893027187874292913927407"), 1,
		 Cert {
		     factorization: vec![
			 (pb(b"2"), 1, Small),
			 (pb(b"3"), 1, Small),
			 (pb(b"277"), 1, Small),
			 (pb(b"350343741906072820209310645555913"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 3, Small),
				  (pb(b"522744931663"), 1,
				   Cert {
				       factorization: vec![
					   (pb(b"2"), 1, Small),
					   (pb(b"3"), 1, Small),
					   (pb(b"41"), 1, Small),
					   (pb(b"89"), 1, Small),
					   (pb(b"421"), 1, Small),
					   (pb(b"56713"), 1, Small) ],
					   generator: pb(b"3")
				   }
				  ),
				  (pb(b"83775021211475436503"), 1,
				   Cert {
				       factorization: vec![
					   (pb(b"2"), 1, Small),
					   (pb(b"11"), 1, Small),
					   (pb(b"653"), 1, Small),
					   (pb(b"564643"), 1,
					    Cert {
						factorization: vec![
						    (pb(b"2"), 1, Small),
						    (pb(b"3"), 2, Small),
						    (pb(b"13"), 1, Small),
						    (pb(b"19"), 1, Small),
						    (pb(b"127"), 1, Small) ],
						    generator: pb(b"5")
					    }
					   ),
					   (pb(b"10327726679"), 1,
					    Cert {
						factorization: vec![
						    (pb(b"2"), 1, Small),
						    (pb(b"17"), 1, Small),
						    (pb(b"19"), 1, Small),
						    (pb(b"569"), 1, Small),
						    (pb(b"28097"), 1, Small) ],
						    generator: pb(b"7")
					    }
					   ) ],
					   generator: pb(b"5")
				   }
			      ) ],
			      generator: pb(b"3")
			  }
		     ) ],
		     generator: pb(b"3")
		 }
		),
		(pb(b"2440563294432588452310063876982204011061"), 1,
		 Cert {
		     factorization: vec![
			 (pb(b"2"), 2, Small),
			 (pb(b"3"), 1, Small),
			 (pb(b"5"), 1, Small),
			 (pb(b"6827"), 1, Small),
			 (pb(b"19571"), 1, Small),
			 (pb(b"64231"), 1, Small),
			 (pb(b"18992539"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 1, Small),
				  (pb(b"3"), 2, Small),
				  (pb(b"1055141"), 1,
				   Cert {
				       factorization: vec![
					   (pb(b"2"), 2, Small),
					   (pb(b"5"), 1, Small),
					   (pb(b"52757"), 1, Small) ],
					   generator: pb(b"2")
				   }
				  ) ],
				  generator: pb(b"2")
			  }
			 ),
			 (pb(b"377723741"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 2, Small),
				  (pb(b"5"), 1, Small),
				  (pb(b"367"), 1, Small),
				  (pb(b"51461"), 1, Small) ],
				  generator: pb(b"3")
			  }
			 ),
			 (pb(b"660684187"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 1, Small),
				  (pb(b"3"), 2, Small),
				  (pb(b"67"), 1, Small),
				  (pb(b"547831"), 1,
				   Cert {
				       factorization: vec![
					   (pb(b"2"), 1, Small),
					   (pb(b"3"), 3, Small),
					   (pb(b"5"), 1, Small),
					   (pb(b"2029"), 1, Small) ],
					   generator: pb(b"3")
				   }
				  ) ],
				  generator: pb(b"2")
			  }
			 ) ],
			 generator: pb(b"2")
		 }
		),
		(pb(b"2987936166061269764733822017919288608395313"), 1,
		 Cert {
		     factorization: vec![
			 (pb(b"2"), 4, Small),
			 (pb(b"19"), 1, Small),
			 (pb(b"503"), 1, Small),
			 (pb(b"10163"), 1, Small),
			 (pb(b"42853043"), 1,
			  Cert {
			      factorization: vec![
				  (pb(b"2"), 1, Small),
				  (pb(b"21426521"), 1,
				   Cert {
				       factorization: vec![
					   (pb(b"2"), 3, Small),
					   (pb(b"5"), 1, Small),
					   (pb(b"535663"), 1,
					    Cert {
						factorization: vec![
						    (pb(b"2"), 1, Small),
						    (pb(b"3"), 2, Small),
						    (pb(b"29759"), 1, Small) ],
						    generator: pb(b"3")
					    }
					   ) ],
					   generator: pb(b"17")
				   }
				  ) ],
				  generator: pb(b"2")
			  }
		     ),
		     (pb(b"518580685877"), 1,
		      Cert {
			  factorization: vec![
			      (pb(b"2"), 2, Small),
			      (pb(b"11"), 1, Small),
			      (pb(b"17"), 1, Small),
			      (pb(b"73"), 1, Small),
			      (pb(b"1087"), 1, Small),
			      (pb(b"8737"), 1, Small) ],
			      generator: pb(b"2")
		      }
		     ),
		     (pb(b"86518666347907"), 1,
		      Cert {
			  factorization: vec![
			      (pb(b"2"), 1, Small),
			      (pb(b"3"), 1, Small),
			      (pb(b"13"), 1, Small),
			      (pb(b"168601"), 1, Small),
			      (pb(b"6578927"), 1,
			       Cert {
				   factorization: vec![
				       (pb(b"2"), 1, Small),
				       (pb(b"3289463"), 1,
					Cert {
					    factorization: vec![
						(pb(b"2"), 1, Small),
						(pb(b"11"), 1, Small),
						(pb(b"149521"), 1, Small) ],
						generator: pb(b"5")
					}
				       ) ],
				       generator: pb(b"5")
			       }
			      ) ],
			      generator: pb(b"5")
		      }
		     ) ],
		     generator: pb(b"3")
		 }
		) ],
		generator: pb(b"7")
	    }
        ).unwrap()

    }
}

