#[cfg(test)]
mod test {
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

