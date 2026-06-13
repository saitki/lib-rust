//! Implementaciones de [`XdrEncode`]/[`XdrDecode`]/[`XdrLen`] para tipos
//! primitivos XDR y contenedores de la stdlib.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{decode_opaque, decode_u32, encode_opaque, ensure, padding};
use crate::{XdrDecode, XdrEncode, XdrError, XdrLen};

// --- Enteros y reales (4 u 8 bytes, big-endian) ------------------------------

macro_rules! prim {
    ($t:ty, $get:ident, $put:ident, $n:literal) => {
        impl XdrEncode for $t {
            #[inline]
            fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
                buf.$put(*self);
                Ok(())
            }
        }
        impl XdrDecode for $t {
            #[inline]
            fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
                ensure(buf, $n)?;
                Ok(buf.$get())
            }
        }
    };
}

// XDR int/unsigned int (4 bytes) y hyper/unsigned hyper (8 bytes).
prim!(i32, get_i32, put_i32, 4);
prim!(u32, get_u32, put_u32, 4);
prim!(i64, get_i64, put_i64, 8);
prim!(u64, get_u64, put_u64, 8);
// XDR float/double (incluidos por completitud de la RFC 4506; NFS no los usa).
prim!(f32, get_f32, put_f32, 4);
prim!(f64, get_f64, put_f64, 8);

// --- bool --------------------------------------------------------------------

impl XdrEncode for bool {
    #[inline]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        buf.put_u32(u32::from(*self));
        Ok(())
    }
}
impl XdrDecode for bool {
    #[inline]
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        match decode_u32(buf)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(XdrError::InvalidBool(other)),
        }
    }
}

// --- void (struct vacío / procedimiento NULL) --------------------------------

impl XdrEncode for () {
    #[inline]
    fn encode(&self, _buf: &mut BytesMut) -> Result<(), XdrError> {
        Ok(())
    }
}
impl XdrDecode for () {
    #[inline]
    fn decode(_buf: &mut Bytes) -> Result<Self, XdrError> {
        Ok(())
    }
}

// --- string<> (UTF-8) --------------------------------------------------------

impl XdrEncode for str {
    #[inline]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        encode_opaque(buf, self.as_bytes(), usize::MAX)
    }
}
impl XdrEncode for String {
    #[inline]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        encode_opaque(buf, self.as_bytes(), usize::MAX)
    }
}
impl XdrDecode for String {
    #[inline]
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let raw = decode_opaque(buf, usize::MAX)?;
        core::str::from_utf8(&raw)
            .map(str::to_owned)
            .map_err(|_| XdrError::InvalidUtf8)
    }
}

// --- opaque<> de longitud variable (Bytes, zero-copy) ------------------------

impl XdrEncode for Bytes {
    #[inline]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        encode_opaque(buf, self, usize::MAX)
    }
}
impl XdrDecode for Bytes {
    #[inline]
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        decode_opaque(buf, usize::MAX)
    }
}

// --- opaque[N] de longitud fija ([u8; N]) ------------------------------------
//
// Nota: solo se implementa para `u8` (opaque fijo). `u8` no es un tipo XDR
// independiente, por lo que no implementa los traits y no colisiona con un
// futuro `impl` genérico de arrays de otros tipos.

impl<const N: usize> XdrEncode for [u8; N] {
    #[inline]
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        buf.put_slice(self);
        buf.put_bytes(0, padding(N));
        Ok(())
    }
}
impl<const N: usize> XdrDecode for [u8; N] {
    #[inline]
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let pad = padding(N);
        ensure(buf, N + pad)?;
        let mut arr = [0u8; N];
        buf.copy_to_slice(&mut arr);
        buf.advance(pad);
        Ok(arr)
    }
}

// --- arrays de longitud variable (Vec<T>) ------------------------------------

impl<T: XdrEncode> XdrEncode for Vec<T> {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        if self.len() > u32::MAX as usize {
            return Err(XdrError::LengthOverflow(self.len()));
        }
        buf.put_u32(self.len() as u32);
        for item in self {
            item.encode(buf)?;
        }
        Ok(())
    }
}
impl<T: XdrDecode> XdrDecode for Vec<T> {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        let count = decode_u32(buf)? as usize;
        // Todo elemento XDR ocupa >= 4 bytes, así que un array válido no puede
        // declarar más elementos que bytes quedan: cota anti-OOM.
        if count > buf.remaining() {
            return Err(XdrError::Truncated {
                needed: count,
                had: buf.remaining(),
            });
        }
        let mut out = Vec::with_capacity(count.min(buf.remaining() / 4 + 1));
        for _ in 0..count {
            out.push(T::decode(buf)?);
        }
        Ok(out)
    }
}

// --- optional (Option<T>, "puntero" XDR) -------------------------------------

impl<T: XdrEncode> XdrEncode for Option<T> {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), XdrError> {
        match self {
            Some(value) => {
                buf.put_u32(1);
                value.encode(buf)
            }
            None => {
                buf.put_u32(0);
                Ok(())
            }
        }
    }
}
impl<T: XdrDecode> XdrDecode for Option<T> {
    fn decode(buf: &mut Bytes) -> Result<Self, XdrError> {
        match decode_u32(buf)? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(buf)?)),
            other => Err(XdrError::InvalidBool(other)),
        }
    }
}

// --- XdrLen (para los chequeos de #[xdr(limit = N)]) -------------------------

impl XdrLen for Bytes {
    fn xdr_len(&self) -> usize {
        self.len()
    }
}
impl XdrLen for str {
    fn xdr_len(&self) -> usize {
        self.len()
    }
}
impl XdrLen for String {
    fn xdr_len(&self) -> usize {
        self.len()
    }
}
impl<T> XdrLen for Vec<T> {
    fn xdr_len(&self) -> usize {
        self.len()
    }
}
