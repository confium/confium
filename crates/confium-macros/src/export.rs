//! Implementation of the `#[export]` proc-macro.
//!
//! Emits the plugin lifecycle symbols every Confium plugin must export:
//!
//! - `cfmp_interface_version` → returns `0` (current plugin contract).
//! - `cfmp_initialize` / `cfmp_finalize` → no-op success.
//! - `cfmp_query_interfaces` → packed `name + NUL + version_byte + NUL`
//!   byte stream enumerating the interfaces registered by
//!   `#[plugin_interface]` in this crate.
//! - `cfmp_metadata` → present only when the `metadata(...)` sub-arg
//!   is supplied on the `#[export]` attribute.
//!
//! The macro does not yet auto-discover interfaces declared via
//! `#[plugin_interface]` — for the proof-of-concept the plugin author
//! declares the interfaces list explicitly via the `interfaces(...)`
//! sub-arg. Future work will use a link-time list collected by
//! `#[plugin_interface]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Token;
use syn::parse::ParseStream;

/// Entry point invoked by the `#[export]` attribute.
pub fn export_impl(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<TokenStream> {
    let args = parse_export_attr(attr)?;
    let item_ast: syn::Item = syn::parse2(item)?;

    // ---- cfmp_query_interfaces payload ----
    //
    // Pack the declared interfaces into a single `&'static [u8]` of
    // `name + NUL + version_byte + NUL` entries, terminated by an
    // empty name (a leading NUL). The loader's
    // `enumerate_plugin_interfaces` parses this exact shape.
    let mut payload: Vec<u8> = Vec::new();
    for iface in &args.interfaces {
        payload.extend_from_slice(iface.name.as_bytes());
        payload.push(0); // NUL terminator for name
        payload.push(iface.version);
        payload.push(0); // NUL terminator for version byte
    }
    payload.push(0); // empty name terminator

    let payload_len = payload.len();
    let payload_literals: Vec<proc_macro2::TokenStream> = payload
        .iter()
        .map(|b| {
            let lit = *b;
            quote! { #lit }
        })
        .collect();

    // ---- cfmp_metadata ----
    let metadata_symbol = if args.metadata.is_empty() {
        // No metadata declared — skip the symbol entirely. The loader
        // treats a missing `cfmp_metadata` as "no metadata" (the plugin
        // is still loadable but isn't eligible for registry publishing).
        TokenStream::new()
    } else {
        let mut builder_calls: Vec<TokenStream> = Vec::new();
        for (key, val) in &args.metadata {
            match key.as_str() {
                "name" => builder_calls.push(quote! { .name(#val) }),
                "version" => builder_calls.push(quote! { .version(#val) }),
                "vendor" => builder_calls.push(quote! { .vendor(#val) }),
                "license" => builder_calls.push(quote! { .license(#val) }),
                "homepage_url" => builder_calls.push(quote! { .homepage_url(#val) }),
                "source_url" => builder_calls.push(quote! { .source_url(#val) }),
                "issue_tracker_url" => builder_calls.push(quote! { .issue_tracker_url(#val) }),
                "description" => builder_calls.push(quote! { .description(#val) }),
                _ => {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        format!("unknown metadata field `{key}`"),
                    ));
                }
            }
        }
        quote! {
            // The metadata builder uses CString (non-const), so the
            // plugin-owned value is constructed on first access via
            // LazyLock and lives for the rest of the process lifetime —
            // matching the plugin contract that `cfmp_metadata`'s
            // returned pointer is valid for the plugin's lifetime.
            #[doc(hidden)]
            static __CONFIUM_PLUGIN_METADATA: std::sync::LazyLock<
                ::confium_api::PluginMetadata
            > = std::sync::LazyLock::new(|| {
                ::confium_api::PluginMetadataBuilder::new()
                    #(#builder_calls)*
                    .build()
            });

            #[unsafe(no_mangle)]
            pub extern "C" fn cfmp_metadata() -> *const ::confium_api::PluginMetadata {
                &*__CONFIUM_PLUGIN_METADATA
            }
        }
    };

    Ok(quote! {
        #item_ast

        // ---- cfmp_interface_version ----
        //
        // The plugin contract version this plugin speaks. Currently 0.
        // Bumped only when the contract wire shape (e.g. the
        // `cfmp_query_interfaces` payload format) changes incompatibly.
        #[unsafe(no_mangle)]
        pub extern "C" fn cfmp_interface_version(
            _cfm: *const std::ffi::c_void,
        ) -> u32 {
            0
        }

        // ---- cfmp_initialize / cfmp_finalize ----
        //
        // No-op success. Plugin authors who need lifecycle hooks can
        // override these by hand-defining the symbols; the macro's
        // versions are the minimum viable no-ops.
        #[unsafe(no_mangle)]
        pub extern "C" fn cfmp_initialize(
            _cfm: *const std::ffi::c_void,
            _opts: *const std::ffi::c_void,
        ) -> u32 {
            0
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn cfmp_finalize(
            _cfm: *const std::ffi::c_void,
        ) -> u32 {
            0
        }

        // ---- cfmp_query_interfaces ----
        //
        // Return the packed `name + NUL + version_byte + NUL ... + NUL`
        // byte stream the loader parses. The static is `&'static` so
        // the returned pointer is valid for the plugin's lifetime.
        #[doc(hidden)]
        static __CONFIUM_QUERY_INTERFACES_PAYLOAD: [u8; #payload_len] =
            [#(#payload_literals),*];

        #[unsafe(no_mangle)]
        pub extern "C" fn cfmp_query_interfaces(
            _cfm: *const std::ffi::c_void,
        ) -> *const u8 {
            __CONFIUM_QUERY_INTERFACES_PAYLOAD.as_ptr()
        }

        #metadata_symbol
    })
}

/// Parsed arguments to the `#[export]` attribute.
struct ExportArgs {
    /// `(name, version)` pairs declared via `interfaces(hash = 0, ...)`.
    interfaces: Vec<InterfaceEntry>,
    /// `(key, value)` pairs declared via `metadata(name = "...", ...)`.
    metadata: Vec<(String, String)>,
}

fn parse_export_attr(attr: TokenStream) -> syn::Result<ExportArgs> {
    if attr.is_empty() {
        return Ok(ExportArgs {
            interfaces: Vec::new(),
            metadata: Vec::new(),
        });
    }

    let parser = syn::punctuated::Punctuated::<ExportArg, Token![,]>::parse_terminated;
    let pairs = syn::parse::Parser::parse2(parser, attr)?;
    let mut interfaces = Vec::new();
    let mut metadata = Vec::new();
    for arg in pairs {
        match arg {
            ExportArg::Interfaces(entries) => interfaces.extend(entries),
            ExportArg::Metadata(pairs) => metadata.extend(pairs),
        }
    }
    Ok(ExportArgs {
        interfaces,
        metadata,
    })
}

enum ExportArg {
    Interfaces(Vec<InterfaceEntry>),
    Metadata(Vec<(String, String)>),
}

impl syn::parse::Parse for ExportArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;
        let content;
        let _ = syn::parenthesized!(content in input);

        if ident == "interfaces" {
            let entries = content.parse_terminated(InterfaceEntry::parse, Token![,])?;
            Ok(ExportArg::Interfaces(entries.into_iter().collect()))
        } else if ident == "metadata" {
            let pairs = content.parse_terminated(MetadataPair::parse, Token![,])?;
            Ok(ExportArg::Metadata(
                pairs.into_iter().map(|p| p.into_pair()).collect(),
            ))
        } else {
            Err(syn::Error::new(
                ident.span(),
                "unknown argument; expected `interfaces(...)` or `metadata(...)`",
            ))
        }
    }
}

struct InterfaceEntry {
    name: String,
    version: u8,
}

impl InterfaceEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: syn::Ident = input.parse()?;
        let _: Token![=] = input.parse()?;
        let version: syn::LitInt = input.parse()?;
        Ok(InterfaceEntry {
            name: name.to_string(),
            version: version
                .base10_parse()
                .map_err(|e| syn::Error::new_spanned(version, e))?,
        })
    }
}

struct MetadataPair {
    key: String,
    val: String,
}

impl MetadataPair {
    fn into_pair(self) -> (String, String) {
        (self.key, self.val)
    }

    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;
        let _: Token![=] = input.parse()?;
        let lit: syn::LitStr = input.parse()?;
        Ok(MetadataPair {
            key: ident.to_string(),
            val: lit.value(),
        })
    }
}
