use std::str::FromStr;

use pest::iterators::Pair;
use smb_dtyp::Guid;
use syn::ItemStruct;

type IdlRule = super::idl::syntax::Rule;

pub fn generate_interface(idl: Pair<IdlRule>, struct_name: &str) -> proc_macro2::TokenStream {
    if !matches!(idl.as_rule(), IdlRule::interface) {
        panic!("Expected interface rule");
    }

    let interface_header = read_interface_header(&idl, struct_name);
    dbg!(&interface_header);

    let struct_name = syn::Ident::new(struct_name, proc_macro2::Span::call_site());
    let interface_struct: ItemStruct = syn::parse_quote! {
        struct #struct_name;
    };
    quote::quote! {
        #interface_struct
    }
}

#[derive(Debug)]
enum RpcPointerType {
    Ref,
    Unique,
    Full,
}

#[derive(Debug)]
struct RpcInterfaceHeaderInfo {
    uuid: Guid,
    version: String,
    pointer_default: Option<RpcPointerType>,
    me_union: bool,
}

fn read_interface_header(idl: &Pair<IdlRule>, _struct_name: &str) -> RpcInterfaceHeaderInfo {
    // Interface := header + body
    let header = idl
        .clone()
        .into_inner()
        .find(|pair| matches!(pair.as_rule(), IdlRule::interface_header))
        .expect("Interface must have a header");

    let mut pointer_default: Option<RpcPointerType> = None;
    let mut uuid: Option<Guid> = None;
    let mut version = String::new();
    let mut me_union = false;

    // Header := interface_attributes
    let interface_attributes = header
        .into_inner()
        .next()
        .expect("Header must have attributes");
    for attribute in interface_attributes.into_inner() {
        match attribute.as_rule() {
            IdlRule::interface_attribute => {
                let attribute = attribute.into_inner().next().unwrap();
                match attribute.as_rule() {
                    IdlRule::uuid_attribute => {
                        // uuid(...) - Uuid_rep
                        let uuid_rep = attribute
                            .into_inner()
                            .find(|pair| matches!(pair.as_rule(), IdlRule::Uuid_rep))
                            .expect("uuid attribute must have Uuid_rep");
                        let uuid_str = uuid_rep.as_str();
                        uuid = Guid::from_str(uuid_str)
                            .expect("Invalid UUID format")
                            .into();
                    }
                    IdlRule::pointer_default_attribute => {
                        // pointer_default(ptr_attr)
                        let ptr_attr = attribute
                            .into_inner()
                            .find(|pair| matches!(pair.as_rule(), IdlRule::ptr_attr))
                            .expect("pointer_default must have ptr_attr");
                        let ptr_type = match ptr_attr.as_str() {
                            "ref" => RpcPointerType::Ref,
                            "unique" => RpcPointerType::Unique,
                            "full" => RpcPointerType::Full,
                            other => panic!("Unknown pointer type: {}", other),
                        };
                        pointer_default = Some(ptr_type);
                    }
                    IdlRule::version_attribute => {
                        // version(major(.minor)?)
                        let mut version_parts = attribute.into_inner();
                        let major = version_parts
                            .next()
                            .expect("version must have major part")
                            .as_str();
                        let minor = version_parts.next().map(|p| p.as_str()).unwrap_or("0");
                        version = format!("{}.{}", major, minor);
                    }
                    IdlRule::ms_union_attribute => {
                        me_union = true;
                    }
                    _ => panic!(
                        "Unexpected attribute in interface attributes: {:?}",
                        attribute.as_rule()
                    ),
                }
            }
            _ => panic!("Unexpected rule in interface attributes"),
        }
    }

    RpcInterfaceHeaderInfo {
        uuid: uuid.expect("Interface must have a UUID"),
        version,
        pointer_default,
        me_union,
    }
}
