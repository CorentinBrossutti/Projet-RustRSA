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
            assert_eq!(b, b.expl_r(2).join());
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


    #[test]
    fn f_unf()
    {
        let s = "test";
        let msg = Message::str(s).build();

        assert_eq!(s, msg.to_str().unwrap());
    }
}


mod engines
{
    use crate::{engines::Engine, rsa::Rsa};
    use num_bigint::BigUint;


    #[test]
    fn pad_unpad()
    {
        let p = BigUint::from(12345u16);
        let mut pp = p.clone();
        let rsa = Rsa;

        rsa.pad(&mut pp, 1);
        rsa.unpad(&mut pp, 1);

        assert_eq!(p, pp);
    }


    mod rsa
    {
        use crate::{engines::Engine, rsa::Rsa, messages::*};
        use num_bigint::BigUint;


        #[test]
        fn generate()
        {
            let rsa = Rsa;
            rsa.generate();
        }

        #[test]
        fn encode_decode()
        {
            let p = BigUint::from(12345u16);
            let mut pp = p.clone();
            let rsa = Rsa;
            let k = rsa.generate();

            rsa.encode(&mut pp, &k.0, 1);
            rsa.decode(&mut pp, &k.1, 1);

            assert_eq!(p, pp);
        }

        #[test]
        fn encrypt_decrypt()
        {
            let smsg = "test";
            let mut msg = Message::str(smsg).build();
            let rsa = Rsa;
            let k = rsa.generate();

            rsa.encrypt(&mut msg, &k.0);
            rsa.decrypt(&mut msg, &k.1);

            assert_eq!(smsg, msg.to_str().unwrap());
        }
    }


    mod cesar
    {
        use crate::{engines::Engine, cesar::Cesar, messages::*};
        use num_bigint::BigUint;


        #[test]
        fn encode_decode()
        {
            let p = BigUint::from(12345u16);
            let mut pp = p.clone();
            let cesar = Cesar;
            let k = cesar.generate();

            cesar.encode(&mut pp, &k, 1);
            cesar.decode(&mut pp, &k, 1);

            assert_eq!(p, pp);
        }

        #[test]
        fn encrypt_decrypt()
        {
            let smsg = "test";
            let mut msg = Message::str(smsg).build();
            let cesar = Cesar;
            let k = cesar.generate();

            cesar.encrypt(&mut msg, &k);
            cesar.decrypt(&mut msg, &k);

            assert_eq!(smsg, msg.to_str().unwrap());
        }
    }
}
