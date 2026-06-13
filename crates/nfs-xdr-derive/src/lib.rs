//! Macros derive para XDR (`XdrEncode` / `XdrDecode`).
//!
//! Equivalente funcional al código que `rpcgen` genera en libnfs (C): a partir
//! de un `struct` o `enum` Rust genera la (de)serialización XDR alineada a 4
//! bytes.
//!
//! ## Estructuras
//!
//! Cada campo se (de)codifica en orden de declaración:
//!
//! ```ignore
//! #[derive(XdrEncode, XdrDecode)]
//! struct Fattr3 { mode: u32, uid: u32, size: u64 }
//! ```
//!
//! Con límite de longitud para `opaque<N>` / `string<N>`:
//!
//! ```ignore
//! #[derive(XdrEncode, XdrDecode)]
//! struct NfsFh3 { #[xdr(limit = 64)] data: bytes::Bytes }
//! ```
//!
//! ## Enums XDR (`#[xdr(enum32)]`)
//!
//! Variantes unitarias con discriminante explícito; se serializan como `int`:
//!
//! ```ignore
//! #[derive(XdrEncode, XdrDecode)]
//! #[xdr(enum32)]
//! enum Nfsstat3 { Ok = 0, Perm = 1, Noent = 2 }
//! ```
//!
//! ## Uniones discriminadas (`#[xdr(union)]`)
//!
//! El discriminante (`int`) precede a los datos del brazo activo:
//!
//! ```ignore
//! #[derive(XdrEncode, XdrDecode)]
//! #[xdr(union)]
//! enum PostOpAttr {
//!     #[xdr(case = 0)] Absent,
//!     #[xdr(case = 1)] Present(Fattr3),
//! }
//! ```

use proc_macro::TokenStream;
use proc_macro2::{Literal, Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Fields, Index, LitInt, Type};

/// Deriva [`XdrEncode`](trait@nfs_xdr::XdrEncode).
#[proc_macro_derive(XdrEncode, attributes(xdr))]
pub fn derive_xdr_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_encode(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Deriva [`XdrDecode`](trait@nfs_xdr::XdrDecode).
#[proc_macro_derive(XdrDecode, attributes(xdr))]
pub fn derive_xdr_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_decode(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

// --- Opciones del contenedor / campo / variante -----------------------------

#[derive(Default)]
struct Container {
    union: bool,
    enum32: bool,
}

fn parse_container(attrs: &[Attribute]) -> syn::Result<Container> {
    let mut c = Container::default();
    for attr in attrs {
        if !attr.path().is_ident("xdr") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("union") {
                c.union = true;
                Ok(())
            } else if meta.path.is_ident("enum32") {
                c.enum32 = true;
                Ok(())
            } else {
                Err(meta.error("atributo de contenedor xdr desconocido (usa `union` o `enum32`)"))
            }
        })?;
    }
    Ok(c)
}

fn parse_field_limit(attrs: &[Attribute]) -> syn::Result<Option<u64>> {
    let mut limit = None;
    for attr in attrs {
        if !attr.path().is_ident("xdr") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("limit") {
                let lit: LitInt = meta.value()?.parse()?;
                limit = Some(lit.base10_parse::<u64>()?);
                Ok(())
            } else {
                Err(meta.error("atributo de campo xdr desconocido (usa `limit = N`)"))
            }
        })?;
    }
    Ok(limit)
}

fn parse_variant_case(attrs: &[Attribute]) -> syn::Result<Option<i64>> {
    let mut case = None;
    for attr in attrs {
        if !attr.path().is_ident("xdr") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("case") {
                let lit: LitInt = meta.value()?.parse()?;
                case = Some(lit.base10_parse::<i64>()?);
                Ok(())
            } else {
                Err(meta.error("atributo de variante xdr desconocido (usa `case = N`)"))
            }
        })?;
    }
    Ok(case)
}

// --- Helpers de generación ---------------------------------------------------

fn usize_lit(n: u64) -> Literal {
    Literal::usize_suffixed(n as usize)
}

fn i32_lit(n: i64) -> Literal {
    Literal::i32_suffixed(n as i32)
}

/// Genera la decodificación de un valor de tipo `ty`, con chequeo de límite
/// opcional.
fn decode_value(ty: &Type, limit: Option<u64>) -> TokenStream2 {
    let base = quote! { <#ty as ::nfs_xdr::XdrDecode>::decode(buf)? };
    match limit {
        None => base,
        Some(n) => {
            let lit = usize_lit(n);
            quote! {{
                let __v = #base;
                let __len = ::nfs_xdr::XdrLen::xdr_len(&__v);
                if __len > #lit {
                    return ::core::result::Result::Err(
                        ::nfs_xdr::XdrError::LimitExceeded { len: __len, limit: #lit });
                }
                __v
            }}
        }
    }
}

/// Genera la codificación de un valor accesible por `access` (una expresión de
/// tipo referencia), con chequeo de límite opcional.
fn encode_access(access: &TokenStream2, limit: Option<u64>) -> TokenStream2 {
    match limit {
        None => quote! { ::nfs_xdr::XdrEncode::encode(#access, buf)?; },
        Some(n) => {
            let lit = usize_lit(n);
            quote! {{
                let __len = ::nfs_xdr::XdrLen::xdr_len(#access);
                if __len > #lit {
                    return ::core::result::Result::Err(
                        ::nfs_xdr::XdrError::LimitExceeded { len: __len, limit: #lit });
                }
                ::nfs_xdr::XdrEncode::encode(#access, buf)?;
            }}
        }
    }
}

/// Construye un valor decodificando los campos de `fields` en orden, con el
/// camino de construcción `path` (`Self` o `Self::Variant`).
fn construct(path: &TokenStream2, fields: &Fields) -> syn::Result<TokenStream2> {
    match fields {
        Fields::Named(named) => {
            let inits = named
                .named
                .iter()
                .map(|f| {
                    let name = f.ident.as_ref().unwrap();
                    let value = decode_value(&f.ty, parse_field_limit(&f.attrs)?);
                    Ok(quote! { #name: #value })
                })
                .collect::<syn::Result<Vec<_>>>()?;
            Ok(quote! { #path { #(#inits),* } })
        }
        Fields::Unnamed(unnamed) => {
            let inits = unnamed
                .unnamed
                .iter()
                .map(|f| Ok(decode_value(&f.ty, parse_field_limit(&f.attrs)?)))
                .collect::<syn::Result<Vec<_>>>()?;
            Ok(quote! { #path( #(#inits),* ) })
        }
        Fields::Unit => Ok(quote! { #path }),
    }
}

// --- Expansión de XdrEncode --------------------------------------------------

fn expand_encode(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (ig, tg, wc) = input.generics.split_for_impl();
    let body = match &input.data {
        Data::Struct(s) => struct_encode(&s.fields)?,
        Data::Enum(e) => {
            let c = parse_container(&input.attrs)?;
            if c.union {
                union_encode(&e.variants)?
            } else if c.enum32 {
                enum32_encode(&e.variants)?
            } else {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "un enum requiere `#[xdr(union)]` o `#[xdr(enum32)]`",
                ));
            }
        }
        Data::Union(_) => {
            return Err(syn::Error::new(
                Span::call_site(),
                "las uniones de Rust no se soportan; usa un enum con `#[xdr(union)]`",
            ))
        }
    };
    Ok(quote! {
        #[automatically_derived]
        #[allow(clippy::all)]
        impl #ig ::nfs_xdr::XdrEncode for #name #tg #wc {
            fn encode(&self, buf: &mut ::nfs_xdr::BytesMut)
                -> ::core::result::Result<(), ::nfs_xdr::XdrError>
            {
                #body
            }
        }
    })
}

fn struct_encode(fields: &Fields) -> syn::Result<TokenStream2> {
    let stmts = match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .map(|f| {
                let name = f.ident.as_ref().unwrap();
                let access = quote! { &self.#name };
                Ok(encode_access(&access, parse_field_limit(&f.attrs)?))
            })
            .collect::<syn::Result<Vec<_>>>()?,
        Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let idx = Index::from(i);
                let access = quote! { &self.#idx };
                Ok(encode_access(&access, parse_field_limit(&f.attrs)?))
            })
            .collect::<syn::Result<Vec<_>>>()?,
        Fields::Unit => Vec::new(),
    };
    Ok(quote! {
        #(#stmts)*
        ::core::result::Result::Ok(())
    })
}

fn enum32_encode(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::Result<TokenStream2> {
    let arms = variants
        .iter()
        .map(|v| {
            if !matches!(v.fields, Fields::Unit) {
                return Err(syn::Error::new_spanned(
                    v,
                    "las variantes de `#[xdr(enum32)]` deben ser unitarias",
                ));
            }
            let vname = &v.ident;
            let disc = v.discriminant.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(v, "falta el discriminante explícito `= N`")
            })?;
            let expr = &disc.1;
            Ok(quote! { Self::#vname => #expr, })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        let __d: i32 = match self { #(#arms)* };
        ::nfs_xdr::XdrEncode::encode(&__d, buf)
    })
}

fn union_encode(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::Result<TokenStream2> {
    let arms = variants
        .iter()
        .map(|v| {
            let vname = &v.ident;
            let case = parse_variant_case(&v.attrs)?
                .ok_or_else(|| syn::Error::new_spanned(v, "falta `#[xdr(case = N)]`"))?;
            let case_lit = i32_lit(case);
            let (pat, body) = match &v.fields {
                Fields::Unit => (quote! { Self::#vname }, quote! {}),
                Fields::Unnamed(u) => {
                    let binds: Vec<_> = (0..u.unnamed.len())
                        .map(|i| format_ident!("__f{}", i))
                        .collect();
                    let encs = u
                        .unnamed
                        .iter()
                        .zip(&binds)
                        .map(|(f, b)| {
                            let access = quote! { #b };
                            Ok(encode_access(&access, parse_field_limit(&f.attrs)?))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;
                    (quote! { Self::#vname( #(#binds),* ) }, quote! { #(#encs)* })
                }
                Fields::Named(n) => {
                    let binds: Vec<_> = n.named.iter().map(|f| f.ident.clone().unwrap()).collect();
                    let encs = n
                        .named
                        .iter()
                        .map(|f| {
                            let name = f.ident.as_ref().unwrap();
                            let access = quote! { #name };
                            Ok(encode_access(&access, parse_field_limit(&f.attrs)?))
                        })
                        .collect::<syn::Result<Vec<_>>>()?;
                    (
                        quote! { Self::#vname { #(#binds),* } },
                        quote! { #(#encs)* },
                    )
                }
            };
            Ok(quote! {
                #pat => {
                    let __d: i32 = #case_lit;
                    ::nfs_xdr::XdrEncode::encode(&__d, buf)?;
                    #body
                }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        match self { #(#arms)* }
        ::core::result::Result::Ok(())
    })
}

// --- Expansión de XdrDecode --------------------------------------------------

fn expand_decode(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (ig, tg, wc) = input.generics.split_for_impl();
    let body = match &input.data {
        Data::Struct(s) => {
            let cons = construct(&quote! { Self }, &s.fields)?;
            quote! { ::core::result::Result::Ok(#cons) }
        }
        Data::Enum(e) => {
            let c = parse_container(&input.attrs)?;
            if c.union {
                union_decode(&e.variants)?
            } else if c.enum32 {
                enum32_decode(&e.variants)?
            } else {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "un enum requiere `#[xdr(union)]` o `#[xdr(enum32)]`",
                ));
            }
        }
        Data::Union(_) => {
            return Err(syn::Error::new(
                Span::call_site(),
                "las uniones de Rust no se soportan; usa un enum con `#[xdr(union)]`",
            ))
        }
    };
    Ok(quote! {
        #[automatically_derived]
        #[allow(clippy::all)]
        impl #ig ::nfs_xdr::XdrDecode for #name #tg #wc {
            fn decode(buf: &mut ::nfs_xdr::Bytes)
                -> ::core::result::Result<Self, ::nfs_xdr::XdrError>
            {
                #body
            }
        }
    })
}

fn enum32_decode(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::Result<TokenStream2> {
    let arms = variants
        .iter()
        .map(|v| {
            if !matches!(v.fields, Fields::Unit) {
                return Err(syn::Error::new_spanned(
                    v,
                    "las variantes de `#[xdr(enum32)]` deben ser unitarias",
                ));
            }
            let vname = &v.ident;
            let disc = v.discriminant.as_ref().ok_or_else(|| {
                syn::Error::new_spanned(v, "falta el discriminante explícito `= N`")
            })?;
            let expr = &disc.1;
            Ok(quote! {
                if __d == (#expr) { return ::core::result::Result::Ok(Self::#vname); }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        let __d = <i32 as ::nfs_xdr::XdrDecode>::decode(buf)?;
        #(#arms)*
        ::core::result::Result::Err(::nfs_xdr::XdrError::InvalidEnum(__d))
    })
}

fn union_decode(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
) -> syn::Result<TokenStream2> {
    let arms = variants
        .iter()
        .map(|v| {
            let case = parse_variant_case(&v.attrs)?
                .ok_or_else(|| syn::Error::new_spanned(v, "falta `#[xdr(case = N)]`"))?;
            let case_lit = i32_lit(case);
            let vname = &v.ident;
            let cons = construct(&quote! { Self::#vname }, &v.fields)?;
            Ok(quote! {
                if __d == #case_lit { return ::core::result::Result::Ok(#cons); }
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        let __d = <i32 as ::nfs_xdr::XdrDecode>::decode(buf)?;
        #(#arms)*
        ::core::result::Result::Err(::nfs_xdr::XdrError::InvalidUnion(__d as u32))
    })
}
