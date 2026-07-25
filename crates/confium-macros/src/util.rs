//! Shared helpers for the proc-macro implementations.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// A `(name, version)` pair extracted from a `#[plugin_interface]` or
/// `#[export]` attribute.
pub struct InterfaceSpec {
    pub name: String,
    pub version: u8,
}

/// Parse the `name = "hash", version = 0` argument list from a macro
/// attribute (`TokenStream`). Emits a compile error if either field is
/// missing or the types don't match (string literal + integer literal).
pub fn parse_interface_attr(attr: TokenStream) -> syn::Result<InterfaceSpec> {
    let parser = syn::punctuated::Punctuated::<MetaPair, syn::Token![,]>::parse_terminated;
    let pairs = syn::parse::Parser::parse2(parser, attr)?;

    let mut name: Option<String> = None;
    let mut version: Option<u8> = None;
    for pair in pairs {
        match pair {
            MetaPair::Name(s) => name = Some(s),
            MetaPair::Version(n) => version = Some(n),
        }
    }
    let name = name.ok_or_else(|| {
        syn::Error::new(proc_macro2::Span::call_site(), "missing `name = \"...\"`")
    })?;
    let version = version
        .ok_or_else(|| syn::Error::new(proc_macro2::Span::call_site(), "missing `version = N`"))?;
    Ok(InterfaceSpec { name, version })
}

/// One key=value pair from a `#[plugin_interface]` attribute.
enum MetaPair {
    Name(String),
    Version(u8),
}

impl syn::parse::Parse for MetaPair {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;
        let _: syn::Token![=] = input.parse()?;
        if ident == "name" {
            let lit: syn::LitStr = input.parse()?;
            Ok(MetaPair::Name(lit.value()))
        } else if ident == "version" {
            let lit: syn::LitInt = input.parse()?;
            Ok(MetaPair::Version(
                lit.base10_parse()
                    .map_err(|e| syn::Error::new_spanned(lit, e))?,
            ))
        } else {
            Err(syn::Error::new(
                ident.span(),
                "unknown attribute argument; expected `name` or `version`",
            ))
        }
    }
}

/// Generate a unique-ish identifier for an interface — used to name the
/// static registration the macro emits.
#[allow(dead_code)] // reserved for future use by interface modules
pub fn interface_kind_ident(name: &str) -> proc_macro2::Ident {
    format_ident!("__ConfiumIface_{}", name)
}

/// Emit a `[u8; N]` array literal containing the packed
/// `name + NUL + version_byte + NUL` byte stream for one interface,
/// suitable for concatenation into the `cfmp_query_interfaces` payload.
#[allow(dead_code)] // used by future interface modules
pub fn pack_interface_entry(name: &str, version: u8) -> TokenStream {
    let name_bytes = name.as_bytes();
    let mut buf: Vec<u8> = Vec::with_capacity(name_bytes.len() + 3);
    buf.extend_from_slice(name_bytes);
    buf.push(0);
    buf.push(version);
    buf.push(0);
    let bytes = &buf;
    quote! {
        [#(#bytes),*]
    }
}
