//! Property tests: round-trip `decode(encode(x)) == x` y robustez del
//! decodificador ante entrada arbitraria (no debe entrar en pánico ni colgarse).

use bytes::Bytes;
use nfs_xdr::{from_bytes, to_bytes, XdrDecode, XdrEncode};
use proptest::prelude::*;

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
struct Sample {
    a: u32,
    b: i64,
    c: bool,
    name: String,
    items: Vec<u32>,
    maybe: Option<u64>,
}

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
#[xdr(union)]
enum Disc {
    #[xdr(case = 0)]
    Empty,
    #[xdr(case = 1)]
    One(u32),
    #[xdr(case = 2)]
    Pair { x: u32, y: u64 },
}

fn roundtrip<T>(value: &T)
where
    T: XdrEncode + XdrDecode + PartialEq + std::fmt::Debug,
{
    let bytes = to_bytes(value).unwrap();
    let decoded: T = from_bytes(bytes).unwrap();
    assert_eq!(&decoded, value);
}

proptest! {
    #[test]
    fn rt_scalars(a in any::<u32>(), b in any::<i64>(), c in any::<bool>(), d in any::<u64>()) {
        roundtrip(&a);
        roundtrip(&b);
        roundtrip(&c);
        roundtrip(&d);
    }

    #[test]
    fn rt_string(s in ".*") {
        roundtrip(&s);
    }

    #[test]
    fn rt_vec(v in proptest::collection::vec(any::<u32>(), 0..64)) {
        roundtrip(&v);
    }

    #[test]
    fn rt_opaque(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        roundtrip(&Bytes::from(bytes));
    }

    #[test]
    fn rt_struct(
        a in any::<u32>(),
        b in any::<i64>(),
        c in any::<bool>(),
        name in ".*",
        items in proptest::collection::vec(any::<u32>(), 0..32),
        maybe in proptest::option::of(any::<u64>()),
    ) {
        roundtrip(&Sample { a, b, c, name, items, maybe });
    }

    #[test]
    fn rt_union(sel in 0u32..3, x in any::<u32>(), y in any::<u64>()) {
        let value = match sel {
            0 => Disc::Empty,
            1 => Disc::One(x),
            _ => Disc::Pair { x, y },
        };
        roundtrip(&value);
    }

    /// El decodificador nunca debe entrar en pánico ante bytes arbitrarios.
    #[test]
    fn decode_arbitrary_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let bytes = Bytes::from(data);
        let _ = from_bytes::<Sample>(bytes.clone());
        let _ = from_bytes::<Disc>(bytes.clone());
        let _ = from_bytes::<Vec<u32>>(bytes.clone());
        let _ = from_bytes::<String>(bytes.clone());
        let _ = from_bytes::<Bytes>(bytes);
    }
}
