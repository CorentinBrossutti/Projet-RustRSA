mod maths 
{
    mod nutil
    {
        use crate::maths::NumUtil;
        use num_bigint::BigUint;


        #[test]
        fn nu_sz()
        {
            assert_eq!(3,  BigUint::from(321u16).sz(10));
        }

        #[test]
        fn nu_sz_b()
        {
            assert_eq!(2, BigUint::from(432u16).sz_b());
        }
    }


    use crate::maths;
    use crate::maths::{NumUtil, VecUtil};
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;

    #[test]
    fn join_expl()
    {
        let b = BigUint::from(1267122178333u64);
        assert_eq!(b, b.expl_r(2).join());
    }

    #[test]
    fn euclide()
    {
        let (a, b) = (BigUint::from(234u32), BigUint::from(267u32));
        assert_eq!(8u32, maths::euclide(&a, &b).to_u32().unwrap());
    }

    #[test]
    fn modpow()
    {
        let (a, b, c) = (BigUint::from(345u16), BigUint::from(712u16), BigUint::from(87u8));
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
