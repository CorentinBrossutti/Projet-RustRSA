mod maths 
{


    mod nvutil 
    {
        use crate::maths::{NumUtil, VecNumUtil};
        use num_bigint::BigUint;


        #[test]
        fn nu_sz() 
        {
            assert_eq!(3, BigUint::from(321u16).sz(10));
        }

        #[test]
        fn nu_sz_b() 
        {
            assert_eq!(2, BigUint::from(432u16).sz_b());
        }

        #[test]
        fn join_expl() 
        {
            let b = BigUint::from(1267122178333u64);
            assert_eq!(b, b.expl_r(2).rejoin());
        }
    }


    use crate::maths;
    use num_bigint::{BigUint, BigInt};
    use num_traits::ToPrimitive;


    #[test]
    fn euclide() 
    {
        let (a, b) = (BigInt::from(234u32), BigInt::from(267u32));
        assert_eq!(8u32, maths::euclide(&a, &b).to_u32().unwrap());
    }

    #[test]
    fn modpow() 
    {
        let (a, b, c) = (
            BigUint::from(345u16),
            BigUint::from(712u16),
            BigUint::from(87u8),
        );
        assert_eq!(a.modpow(&b, &c), maths::fmodpow(&a, &b, &c));
    }

    #[test]
    fn expcode() 
    {
        let x = BigUint::from(12781u16);
        assert_eq!(2, maths::expcode(&x).unwrap().to_u32().unwrap());
    }

    #[test]
    fn isprime() 
    {
        let p = BigUint::from(5653u16);
        let np = BigUint::from(12782u16);
        assert!(maths::isprime(&p));
        assert!(!maths::isprime(&np));
    }
}


mod messages
{
    use crate::messages::*;
    use num_bigint::BigUint;
    use num_traits::Num;


    #[test]
    fn f_unf()
    {
        let msg = Message::str(String::from("test")).build();

        assert_eq!("test", msg.to_str().unwrap());
    }

    #[test]
    fn ns_uns()
    {
        let msg = Message::nstr(String::from("8a240238dfljqslkfj2378273dfjqldksf8a240238dfljqslkfj2378273dfjqldksf"), true).build();

        assert_eq!(BigUint::from_str_radix("8a240238dfljqslkfj2378273dfjqldksf8a240238dfljqslkfj2378273dfjqldksf", 36).unwrap().to_str_radix(36), msg.to_nstr());
    }

    #[test]
    fn bd_dest()
    {
        let msg = Message::nstr(String::from("8a240238dfljqslkfj2378273dfjqldksf8a240238dfljqslkfj2378273dfjqldksf8a240238dfljqslkfj2378273dfjqldksf8a240238dfljqslkfj2378273dfjqldksf"), true).build();
        let parts = msg.parts.clone();
        let msg = Message::nstr(msg.to_nstr(), true).build();

        for (index, part) in parts.iter().enumerate()
        {
            println!("{}", part);
            assert_eq!(part, &msg.parts[index]);
        }
    }
}


mod keys
{
    use crate::{engines::RsaKey, keys::{Key, NumKey, KeyPair}};
    use num_bigint::BigUint;


    #[test]
    fn ser_str()
    {
        let k = NumKey::from(BigUint::from(9u8));
        assert_eq!("9", k.serialize_str());
    }

    #[test]
    fn from_str()
    {
        assert_eq!(BigUint::from(9u8), NumKey::from_str(String::from("9")).unwrap().value);
    }

    #[test]
    fn from_str_dpair()
    {
        let k = RsaKey::from_str(String::from("9::8::7::6")).unwrap();
        assert_eq!(k.0.0.value, BigUint::from(9u8));
        assert_eq!(k.0.1.value, BigUint::from(8u8));
        assert_eq!(k.1.0.value, BigUint::from(7u8));
        assert_eq!(k.1.1.value, BigUint::from(6u8));
    }

    #[test]
    fn ser_str_dpair()
    {
        let k = KeyPair(
            KeyPair(
                NumKey::from(BigUint::from(9u8)),
                NumKey::from(BigUint::from(8u8))
            ),
            KeyPair(
                NumKey::from(BigUint::from(7u8)),
                NumKey::from(BigUint::from(6u8))
            )
        );

        assert_eq!("9::8::7::6", k.serialize_str());
    }
}


mod engines
{
    use crate::engines::{Engine, Cesar};
    use num_bigint::BigUint;


    #[test]
    fn pad_unpad()
    {
        let p = BigUint::from(12345u16);
        let mut pp = p.clone();
        let rsa = Cesar;

        rsa.pad(&mut pp, 1);
        rsa.unpad(&mut pp, 1);

        assert_eq!(p, pp);
    }


    mod rsa
    {
        use crate::{engines::{Engine, Rsa, RSA_DEF_GEN_THREADS}, maths::{isprime, rand_primelike}, messages::*};
        use std::time::Instant;
        use num_bigint::BigUint;


        #[test]
        fn gen_64()
        {
            let rsa = Rsa;
            let _k = rsa.generate(64u64, RSA_DEF_GEN_THREADS);
        }

        #[test]
        fn gen_128()
        {
            let rsa = Rsa;
            let _k = rsa.generate(128u64, RSA_DEF_GEN_THREADS);
        }

        #[test]
        #[ignore = "Trop long"]
        fn gen_256()
        {
            let rsa = Rsa;
            let _k = rsa.generate(256u64, RSA_DEF_GEN_THREADS);
        }

        #[test]
        #[ignore = "Benchmarking uniquement"]
        fn gen_time()
        {
            let mut tpoint = Instant::now();
            for _ in 0..100
            {
                rand_primelike(64);
            }
            println!("Génération 64 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);
            tpoint = Instant::now();
            for _ in 0..100
            {
                rand_primelike(128);
            }
            println!("Génération 128 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);
            tpoint = Instant::now();
            for _ in 0..100
            {
                rand_primelike(256);
            }
            println!("Génération 256 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);

            let (n64, n128, n256) = (rand_primelike(64), rand_primelike(128), rand_primelike(256));

            tpoint = Instant::now();
            for _ in 0..100
            {
                isprime(&n64);
            }
            println!("Vérification 64 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);
            tpoint = Instant::now();
            for _ in 0..100
            {
                isprime(&n128);
            }
            println!("Vérification 128 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);
            tpoint = Instant::now();
            for _ in 0..100
            {
                isprime(&n256);
            }
            println!("Vérification 256 octets en {} ms soit {} ms par itération.", tpoint.elapsed().as_millis(), tpoint.elapsed().as_millis() / 100);

            panic!();
        }

        #[test]
        fn encode_decode()
        {
            let p = BigUint::from(12345u16);
            let mut pp = p.clone();
            let rsa = Rsa;
            let k = rsa.gen_def();

            rsa.encode(&mut pp, &k.0, 1);
            rsa.decode(&mut pp, &k.1, 1);

            assert_eq!(p, pp);
        }

        #[test]
        fn encrypt_decrypt()
        {
            let mut msg = Message::str(String::from("test rsa")).build();
            let rsa = Rsa;
            let k = rsa.gen_def();

            rsa.encrypt(&mut msg, &k.0);
            let mut msg = Message::parts_str(msg.to_parts_str(), true).build();
            rsa.decrypt(&mut msg, &k.1);

            assert_eq!("test rsa", msg.to_str().unwrap());
        }

        #[test]
        fn e_d_inv()
        {
            let mut msg = Message::str(String::from("test rsa")).build();
            let rsa = Rsa;
            let k = rsa.gen_def();

            rsa.encrypt(&mut msg, &k.1);
            //let mut msg = Message::parts_str(msg.to_parts_str(), true).build();
            rsa.decrypt(&mut msg, &k.0);
            
            assert_eq!("test rsa", msg.to_str().unwrap());
        }

        #[test]
        fn sign_verify()
        {
            let mut msg = Message::str(String::from("test rsa")).build();
            let rsa = Rsa;
            let k = rsa.gen_def();

            rsa.encrypt(&mut msg, &k.1);
            rsa.decrypt(&mut msg, &k.0);

            assert_eq!("test rsa", msg.to_str().unwrap());
        }
    }


    mod cesar
    {
        use crate::{engines::{Engine, Cesar}, messages::*};
        use num_bigint::BigUint;


        #[test]
        fn encode_decode()
        {
            let p = BigUint::from(12345u16);
            let mut pp = p.clone();
            let cesar = Cesar;
            let k = cesar.gen_def();

            cesar.encode(&mut pp, &k, 1);
            cesar.decode(&mut pp, &k, 1);

            assert_eq!(p, pp);
        }

        #[test]
        fn encrypt_decrypt()
        {
            let mut msg = Message::str(String::from("test cesar")).build();
            let cesar = Cesar;
            let k = cesar.gen_def();

            cesar.encrypt(&mut msg, &k);
            let mut msg = Message::parts_str(msg.to_parts_str(), true).build();
            cesar.decrypt(&mut msg, &k);

            assert_eq!("test cesar", msg.to_str().unwrap());
        }
    }
}
