use pest::Parser;
use syn::{Expr, ExprLit, Lit, Meta, parse::Parse};

mod gen_iface;
mod idl;

struct RpcInterfaceAttr {
    idl: String,
}

impl Parse for RpcInterfaceAttr {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let meta: Meta = input.parse()?;
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("idl") => {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(lit), ..
                }) = nv.value
                {
                    Ok(RpcInterfaceAttr { idl: lit.value() })
                } else {
                    Err(syn::Error::new_spanned(nv.value, "expected string literal"))
                }
            }
            _ => Err(syn::Error::new_spanned(meta, "expected `idl = \"...\"`")),
        }
    }
}

fn generate_rpc_interface(attr: RpcInterfaceAttr, struct_name: &str) -> proc_macro::TokenStream {
    let abs_path_idl = std::path::Path::new(&attr.idl);
    if !abs_path_idl.exists() {
        panic!(
            "IDL file does not exist: {}",
            std::path::absolute(abs_path_idl).unwrap().display()
        );
    }
    let idl_content = std::fs::read_to_string(&attr.idl)
        .unwrap_or_else(|_| panic!("Failed to read IDL file: {}", &attr.idl));
    let idl_syntax = idl::syntax::IdlParser::parse(idl::syntax::Rule::interface, &idl_content)
        .expect("Failed to parse IDL interface")
        .next()
        .unwrap();

    gen_iface::generate_interface(idl_syntax, struct_name).into()
}

#[proc_macro_attribute]
pub fn rpc_interface(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let attr = syn::parse_macro_input!(attr as RpcInterfaceAttr);

    let struct_name = {
        let item_ast = syn::parse_macro_input!(item as syn::ItemStruct);
        item_ast.ident.to_string()
    };

    generate_rpc_interface(attr, &struct_name)
}
