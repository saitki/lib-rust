//! Vectores byte-exactos según las reglas de codificación de la RFC 4506.
//!
//! Sirven de prueba de compatibilidad binaria: los bytes esperados se derivan
//! directamente de la especificación XDR (big-endian, relleno a 4 bytes). El
//! cruce final contra una captura de Wireshark de libnfs se hará en cuanto
//! exista el framing ONC-RPC (Fase 2/3), donde los mensajes son observables en
//! la red.

use bytes::Bytes;
use nfs_xdr::{from_bytes, to_bytes, XdrDecode, XdrEncode};

fn enc<T: XdrEncode + ?Sized>(v: &T) -> Vec<u8> {
    to_bytes(v).unwrap().to_vec()
}

#[test]
fn integers_big_endian() {
    assert_eq!(enc(&1u32), [0, 0, 0, 1]);
    assert_eq!(enc(&0xDEAD_BEEFu32), [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(enc(&-1i32), [0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(enc(&1u64), [0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        enc(&-2i64),
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]
    );
}

#[test]
fn bool_encoding() {
    assert_eq!(enc(&true), [0, 0, 0, 1]);
    assert_eq!(enc(&false), [0, 0, 0, 0]);
    // Un bool distinto de 0/1 debe rechazarse.
    let bad = Bytes::from_static(&[0, 0, 0, 2]);
    assert!(from_bytes::<bool>(bad).is_err());
}

#[test]
fn variable_opaque_padding() {
    // opaque<> de 3 bytes -> longitud(4) + datos(3) + 1 byte de relleno.
    let data = Bytes::from_static(&[0xCA, 0xFE, 0xBA]);
    assert_eq!(enc(&data), [0, 0, 0, 3, 0xCA, 0xFE, 0xBA, 0x00]);
    // Round-trip.
    let back: Bytes = from_bytes(to_bytes(&data).unwrap()).unwrap();
    assert_eq!(back, data);
}

#[test]
fn string_padding() {
    // "hello" (5 bytes) -> longitud(4) + 5 datos + 3 relleno = 12 bytes.
    let s = String::from("hello");
    assert_eq!(enc(&s), [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let back: String = from_bytes(to_bytes(&s).unwrap()).unwrap();
    assert_eq!(back, s);
}

#[test]
fn fixed_opaque_no_length_prefix() {
    // opaque[4]: 4 bytes, sin prefijo ni relleno.
    assert_eq!(enc(&[1u8, 2, 3, 4]), [1, 2, 3, 4]);
    // opaque[3]: 3 bytes + 1 relleno, sin prefijo.
    assert_eq!(enc(&[1u8, 2, 3]), [1, 2, 3, 0]);
    let back: [u8; 3] = from_bytes(Bytes::from_static(&[9, 8, 7, 0])).unwrap();
    assert_eq!(back, [9, 8, 7]);
}

#[test]
fn variable_array() {
    let v = vec![1u32, 2, 3];
    assert_eq!(enc(&v), [0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    let back: Vec<u32> = from_bytes(to_bytes(&v).unwrap()).unwrap();
    assert_eq!(back, v);
}

#[test]
fn optional_pointer() {
    assert_eq!(enc(&Some(7u32)), [0, 0, 0, 1, 0, 0, 0, 7]);
    assert_eq!(enc(&None::<u32>), [0, 0, 0, 0]);
    let back: Option<u32> = from_bytes(to_bytes(&Some(7u32)).unwrap()).unwrap();
    assert_eq!(back, Some(7));
}

// --- Tipos derivados ---------------------------------------------------------

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
struct Nfstime3 {
    seconds: u32,
    nseconds: u32,
}

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
struct WithName {
    id: u32,
    name: String,
}

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
struct FhLike {
    #[xdr(limit = 8)]
    handle: Bytes,
}

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
#[xdr(enum32)]
enum Nfsstat3 {
    Ok = 0,
    Perm = 1,
    Noent = 2,
    Stale = 70,
}

#[derive(XdrEncode, XdrDecode, Debug, PartialEq, Clone)]
#[xdr(union)]
enum PostOpAttr {
    #[xdr(case = 0)]
    Absent,
    #[xdr(case = 1)]
    Present(Nfstime3),
}

#[test]
fn derived_struct_in_order() {
    let t = Nfstime3 {
        seconds: 1,
        nseconds: 2,
    };
    assert_eq!(enc(&t), [0, 0, 0, 1, 0, 0, 0, 2]);
    assert_eq!(from_bytes::<Nfstime3>(to_bytes(&t).unwrap()).unwrap(), t);
}

#[test]
fn derived_struct_with_string() {
    let w = WithName {
        id: 1,
        name: "ab".into(),
    };
    // id(4) + len(4) + "ab"(2) + relleno(2)
    assert_eq!(enc(&w), [0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0]);
    assert_eq!(from_bytes::<WithName>(to_bytes(&w).unwrap()).unwrap(), w);
}

#[test]
fn derived_limit_enforced() {
    // 8 bytes: dentro del límite.
    let ok = FhLike {
        handle: Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]),
    };
    assert!(to_bytes(&ok).is_ok());
    // 9 bytes: supera el límite -> error de codificación.
    let too_big = FhLike {
        handle: Bytes::from_static(&[0; 9]),
    };
    assert!(matches!(
        to_bytes(&too_big),
        Err(nfs_xdr::XdrError::LimitExceeded { len: 9, limit: 8 })
    ));
    // Decodificar un opaque de 9 bytes en un campo limitado a 8 también falla.
    let wire = Bytes::from_static(&[0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0]);
    assert!(from_bytes::<FhLike>(wire).is_err());
}

#[test]
fn derived_enum32() {
    assert_eq!(enc(&Nfsstat3::Ok), [0, 0, 0, 0]);
    assert_eq!(enc(&Nfsstat3::Stale), [0, 0, 0, 70]);
    assert_eq!(
        from_bytes::<Nfsstat3>(Bytes::from_static(&[0, 0, 0, 2])).unwrap(),
        Nfsstat3::Noent
    );
    // Discriminante desconocido -> error.
    assert!(matches!(
        from_bytes::<Nfsstat3>(Bytes::from_static(&[0, 0, 0, 99])),
        Err(nfs_xdr::XdrError::InvalidEnum(99))
    ));
}

#[test]
fn derived_union() {
    let absent = PostOpAttr::Absent;
    assert_eq!(enc(&absent), [0, 0, 0, 0]);

    let present = PostOpAttr::Present(Nfstime3 {
        seconds: 5,
        nseconds: 6,
    });
    // disc(0)=1 + seconds(5) + nseconds(6)
    assert_eq!(enc(&present), [0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 6]);

    assert_eq!(
        from_bytes::<PostOpAttr>(to_bytes(&present).unwrap()).unwrap(),
        present
    );
    // Discriminante de union desconocido -> error.
    assert!(matches!(
        from_bytes::<PostOpAttr>(Bytes::from_static(&[0, 0, 0, 9])),
        Err(nfs_xdr::XdrError::InvalidUnion(9))
    ));
}

#[test]
fn trailing_data_rejected() {
    // from_bytes exige consumir el mensaje completo.
    let wire = Bytes::from_static(&[0, 0, 0, 1, 0xFF]);
    assert!(matches!(
        from_bytes::<u32>(wire),
        Err(nfs_xdr::XdrError::TrailingData(1))
    ));
}

#[test]
fn truncated_input_errors() {
    assert!(matches!(
        from_bytes::<u32>(Bytes::from_static(&[0, 0, 1])),
        Err(nfs_xdr::XdrError::Truncated { needed: 4, had: 3 })
    ));
}
