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
//! Interface auto-discovery: the macro iterates the link-time registry
//! (`confium_api::registry::iter`) populated by every
//! `#[plugin_interface]` in the crate, so plugin authors no longer need
//! to repeat the interface list in `#[export]`. An explicit
//! `interfaces(...)` argument is still accepted and is appended to the
//! auto-discovered set — it exists for plugins that hand-roll FFI
//! symbols without `#[plugin_interface]`.

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

    // ---- explicitly-declared interfaces (augment the auto-discovered set) ----
    //
    // Pack the user-supplied `(name, version)` pairs (if any) into
    // token-stream literals for the static the generated
    // `cfmp_query_interfaces` appends at runtime. The auto-discovered
    // interfaces come from the link-time registry populated by
    // `#[plugin_interface]`.
    let explicit_iface_tokens: Vec<TokenStream> = args
        .interfaces
        .iter()
        .map(|e| {
            let name = &e.name;
            let version = e.version;
            quote! { (#name, #version) }
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
        // Builds the packed `name + NUL + version_byte + NUL ... + NUL`
        // byte stream the loader parses. The payload is constructed at
        // call time from two sources:
        //
        // 1. Every `#[plugin_interface]` in this crate, collected at
        //    link time via `confium_api::registry` (auto-discovery).
        // 2. Any explicitly-declared `interfaces(...)` entries from the
        //    `#[export]` attribute (for hand-rolled FFI symbols).
        //
        // Constructing at call time (rather than macro-expansion time)
        // is required because `inventory` submissions are not visible
        // until runtime — they live in linker sections that the
        // `#[plugin_interface]` macro populates after `#[export]`
        // expands.
        #[unsafe(no_mangle)]
        pub extern "C" fn cfmp_query_interfaces(
            _cfm: *const std::ffi::c_void,
        ) -> *const u8 {
            // Explicit entries declared in `#[export(interfaces(...))]`.
            // Compiled into the plugin as a static so the runtime loop
            // can append them without allocating on every call.
            #[doc(hidden)]
            static __CONFIUM_EXPLICIT_IFACES: &[(&str, u8)] = &[
                #(#explicit_iface_tokens),*
            ];

            // Build the payload once and cache it for the plugin's
            // lifetime. `LazyLock` guarantees a single allocation even
            // under concurrent loads.
            //
            // Format: `name\0version` repeated, terminated by a lone
            // `\0` (empty name). The loader's parser advances past the
            // name's NUL and the version byte with `idx = end + 2`, so
            // there is NO trailing NUL after the version byte — the
            // next entry's name begins immediately.
            #[doc(hidden)]
            static __CONFIUM_QUERY_INTERFACES_BUF: std::sync::LazyLock<Vec<u8>> =
                std::sync::LazyLock::new(|| {
                    let mut buf: Vec<u8> = Vec::new();
                    // Auto-discovered interfaces (from #[plugin_interface]).
                    for entry in ::confium_api::registry::iter() {
                        buf.extend_from_slice(entry.name.as_bytes());
                        buf.push(0); // name terminator
                        buf.push(entry.version);
                    }
                    // Explicitly-declared interfaces (from #[export]).
                    for (name, version) in __CONFIUM_EXPLICIT_IFACES {
                        buf.extend_from_slice(name.as_bytes());
                        buf.push(0); // name terminator
                        buf.push(*version);
                    }
                    buf.push(0); // empty name terminator
                    buf
                });

            __CONFIUM_QUERY_INTERFACES_BUF.as_ptr()
        }

        #metadata_symbol
    })
}

/// Parsed arguments to the `#[export]` attribute.
struct ExportArgs {
    /// `(name, version)` pairs declared via `interfaces(hash = 0, ...)`.
    /// Optional now that `#[plugin_interface]` auto-registers; kept for
    /// plugins that hand-roll FFI symbols.
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
