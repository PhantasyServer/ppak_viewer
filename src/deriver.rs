use proc_macro2::{Span, TokenStream};
use pso2packetlib::{
    asciistring::StringRW,
    protocol::{Flags, PacketError, PacketHeader, PacketType},
    AsciiString,
};
use quote::quote;
use std::{
    fmt::Write,
    io::{Cursor, Read, Seek},
    net::Ipv4Addr,
    time::Duration,
};
use syn::{
    punctuated::Punctuated, spanned::Spanned, Attribute, Fields, GenericArgument, Item, LitInt,
    MetaList, PathArguments, Stmt, Token, Type,
};

#[derive(Debug)]
pub struct Data {
    statements: Vec<Stmt>,
}

impl syn::parse::Parse for Data {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let statement = syn::Block::parse_within(input)?;
        Ok(Self {
            statements: statement
                .into_iter()
                .filter(|s| matches!(s, Stmt::Item(Item::Struct(_))))
                .collect(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct PacketStructDef {
    name: String,

    // packet derive
    id: u8,
    subid: u16,
    xor: u32,
    sub: u32,
    flags: Flags,
    is_unnamed: bool,

    fields: Vec<Field>,
}

#[derive(Clone)]
pub struct PacketStruct {
    name: String,

    fields: Vec<FieldRead>,
}

impl PacketStructDef {
    pub fn from_str(string: &str) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_data(&syn::parse_str::<Data>(string)?)
    }
    pub fn from_data(data: &Data) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let mut structs = vec![];
        for i in &data.statements {
            let Stmt::Item(Item::Struct(st)) = i else {
                continue;
            };
            structs.push(Self::from_struct(st)?);
        }

        if structs.is_empty() {
            return Ok(None);
        }
        let mut main = structs.swap_remove(0);
        main.populate_structs(&structs);

        Ok(Some(main))
    }
    pub fn from_struct(st: &syn::ItemStruct) -> Result<Self, Box<dyn std::error::Error>> {
        let mut structure = PacketStructDef {
            name: st.ident.to_string(),
            ..Default::default()
        };
        structure.name = st.ident.to_string();
        if let Some((id, subid)) = get_packet_id(&st.attrs)? {
            structure.id = id;
            structure.subid = subid;
            let xor_sub = get_magic(&st.attrs)?;
            let flags = get_flags(&st.attrs)?;
            if flags.to_string().contains("PACKED") && xor_sub.is_none() {
                return Err(syn::Error::new(st.ident.span(), "No magic provided").into());
            }
            let (xor, sub) = xor_sub.unwrap_or((0, 0));
            structure.xor = xor;
            structure.sub = sub;
        }
        structure.is_unnamed = matches!(st.fields, Fields::Unnamed(_));
        structure.fields = parse_struct_field(st, false)?;

        Ok(structure)
    }
    pub fn id_from_packet(&mut self, data: &[u8], pt: PacketType) {
        let mut data = Cursor::new(&data[4..]);
        let header = PacketHeader::read(&mut data, pt).unwrap();
        self.id = header.id;
        self.subid = header.subid;
        self.flags = header.flag;
    }
    pub fn populate_structs(&mut self, structs: &[PacketStructDef]) {
        for field in &mut self.fields {
            field.field_type.populate_struct(structs);
        }
    }
    fn to_tokenstream(&self) -> Result<TokenStream, Box<dyn std::error::Error>> {
        let mut flags = self
            .flags
            .iter_names()
            .fold(String::new(), |mut s, (f, _)| {
                let _ = write!(s, "Flags::{}|", f);
                s
            });
        flags.pop();
        let flags_stream = if !flags.is_empty() {
            let flags_stream = flags.parse::<TokenStream>()?;
            quote! {#[Flags(#flags_stream)]}
        } else {
            quote! {}
        };
        let id_stream = if self.id != 0 || self.subid != 0 {
            let id = self.id;
            let subid = self.subid;
            quote! {#[Id(#id, #subid)]}
        } else {
            quote! {}
        };
        let packet_derive = if self.id != 0 || self.subid != 0 {
            quote! {PacketReadWrite}
        } else {
            quote! {HelperReadWrite}
        };
        let mut other_structs = TokenStream::new();
        let mut fields = TokenStream::new();
        for field in &self.fields {
            if let FieldType::Struct(st) = &field.field_type {
                other_structs.extend(st.to_tokenstream()?);
            }
            if let FieldType::Vec { inner_type, .. } = &field.field_type {
                if let FieldType::Struct(st) = inner_type.as_ref() {
                    other_structs.extend(st.to_tokenstream()?);
                }
            }
            if let FieldType::FixedVec { inner_type, .. } = &field.field_type {
                if let FieldType::Struct(st) = inner_type.as_ref() {
                    other_structs.extend(st.to_tokenstream()?);
                }
            }
            fields.extend(field.to_tokenstream()?);
        }
        let name = self.name.parse::<TokenStream>()?;
        Ok(quote! {
            #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
            #[cfg_attr(feature = "serde", serde(default))]
            #[derive(Debug, Clone, PartialEq, Default, #packet_derive)]
            #id_stream
            #flags_stream
            pub struct #name {
                #fields
            }
            #other_structs
        })
    }
    pub fn read_from_data(
        &self,
        data: &[u8],
        xor: u32,
        sub: u32,
    ) -> Result<PacketStruct, PacketError> {
        let mut data = Cursor::new(&data[8..]);
        self.read(&mut data, xor, sub)
    }
    pub fn read(
        &self,
        data: &mut (impl Read + Seek),
        mut xor: u32,
        mut sub: u32,
    ) -> Result<PacketStruct, PacketError> {
        let mut fields = vec![];
        if self.xor > 0 {
            xor = self.xor;
        }
        if self.sub > 0 {
            sub = self.sub;
        }
        for field in &self.fields {
            if matches!(field.field_type, FieldType::ConstU16(_)) {
                let _ = data.seek(std::io::SeekFrom::Current(2));
                continue;
            }
            fields.push(field.read(data, xor, sub).map_err(|e| {
                PacketError::CompositeFieldError {
                    // THIS IS UNSAFE! This *should* live as long as self, but DEFINITELY not 'static
                    packet_name: unsafe {
                        std::mem::transmute::<&str, &'static str>(self.name.as_str())
                    },
                    field_name: unsafe {
                        std::mem::transmute::<&str, &'static str>(field.name.as_str())
                    },
                    error: e.into(),
                }
            })?);
        }
        Ok(PacketStruct {
            name: self.name.clone(),
            fields,
        })
    }
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for PacketStructDef {
    fn to_string(&self) -> String {
        syn::parse_file(&self.to_tokenstream().unwrap_or_default().to_string())
            .map(|f| prettyplease::unparse(&f))
            .unwrap_or_default()
    }
}

fn parse_struct_field(data: &syn::ItemStruct, no_seek: bool) -> syn::Result<Vec<Field>> {
    let mut fields = vec![];

    // unnamed struct
    if let Fields::Unnamed(fileds) = &data.fields {
        for (id, field) in fileds.unnamed.iter().enumerate() {
            let field_name = format!("unnamed_{}", id);

            let field = parse_field_type(&field.ty, &field_name, &Settings::default())?;
            fields.push(Field {
                name: field_name,
                field_type: field,
                _no_seek: no_seek,
                ..Default::default()
            });
        }
        return Ok(fields);
    }

    for field in &data.fields {
        let field_name = field.ident.as_ref().unwrap().to_string();

        let mut settings = Settings::default();

        for attr in &field.attrs {
            match &attr.meta {
                syn::Meta::NameValue(_) => {}
                syn::Meta::Path(path) => {
                    let attribute_name = path.get_ident().unwrap().to_string();
                    get_attrs(&mut settings, &attribute_name, None)?;
                }
                syn::Meta::List(list) => {
                    let attribute_name = list.path.get_ident().unwrap().to_string();
                    get_attrs(&mut settings, &attribute_name, Some(list))?;
                }
            }
        }

        let field = parse_field_type(&field.ty, &field_name, &settings)?;
        for const_val in &settings.consts {
            fields.push(Field {
                name: "const".to_string(),
                field_type: const_val.clone(),
                _no_seek: no_seek,
                ..Default::default()
            })
        }
        let mut field = Field {
            name: field_name,
            field_type: field,
            _no_seek: no_seek,
            ..Default::default()
        };

        if let Some(data) = settings.only_on {
            field.only_on = Some(data);
        } else if let Some(data) = settings.not_on {
            field.not_on = Some(data);
        }
        field.seek = settings.seek;
        field.seek_after = settings.seek_after;
        fields.push(field);
    }

    Ok(fields)
}

fn parse_field_type(in_type: &Type, field_name: &str, set: &Settings) -> syn::Result<FieldType> {
    match in_type {
        Type::Path(path) => {
            let type_name_segment = path.path.segments.last().unwrap();
            let type_name = type_name_segment.ident.to_string();
            if !type_name.contains("Vec") {
                return type_read_write(type_name, set);
            }

            // assume type is Vec<T>
            let PathArguments::AngleBracketed(args) = &type_name_segment.arguments else {
                return Err(syn::Error::new(in_type.span(), "Invalid type"));
            };
            let Some(GenericArgument::Type(inner_type)) = &args.args.get(0) else {
                return Err(syn::Error::new(in_type.span(), "Invalid type"));
            };
            let tmp_name = format!("vec_{}_value", field_name);
            let field = parse_field_type(inner_type, &tmp_name, set)?;

            let field = if set.fixed_len == 0 {
                FieldType::Vec {
                    size_type: set.len_size,
                    inner_type: field.into(),
                }
            } else {
                FieldType::FixedVec {
                    size: set.fixed_len as u64,
                    inner_type: field.into(),
                }
            };
            return Ok(field);
        }
        Type::Array(arr) => {
            let inner_type = arr.elem.as_ref();
            let len = match &arr.len {
                syn::Expr::Lit(i) => match &i.lit {
                    syn::Lit::Int(i) => i.base10_parse()?,
                    _ => 0,
                },
                _ => 0,
            };
            let tmp_name = format!("array_{}_value", field_name);
            let field = parse_field_type(inner_type, &tmp_name, set)?;
            let field = FieldType::FixedVec {
                inner_type: field.into(),
                size: len,
            };
            return Ok(field);
        }
        _ => {}
    }
    Err(syn::Error::new(in_type.span(), "Invalid type"))
}

fn type_read_write(full_type_path: String, set: &Settings) -> syn::Result<FieldType> {
    let type_str = full_type_path.split("::").last().unwrap();

    Ok(match type_str {
        "u8" => FieldType::U8,
        "i8" => FieldType::I8,
        "u16" => FieldType::U16,
        "i16" => FieldType::I16,
        "u32" => FieldType::U32,
        "i32" => FieldType::I32,
        "u64" => FieldType::U64,
        "i64" => FieldType::I64,
        "u128" => FieldType::U128,
        "i128" => FieldType::I128,
        "f16" => FieldType::F16,
        "f32" => FieldType::F32,
        "f64" => FieldType::F64,
        "String" => match set.str_type {
            StringType::Unknown => FieldType::String,
            StringType::Fixed(len) => FieldType::FixedString(len),
        },
        "AsciiString" => match set.str_type {
            StringType::Unknown => FieldType::AsciiString,
            StringType::Fixed(len) => FieldType::FixedAsciiString(len),
        },
        "Ipv4Addr" => FieldType::Ipv4,
        "Duration" => FieldType::Duration {
            is_pso_time: set.is_psotime,
        },
        string => FieldType::Unknown {
            name: string.to_string(),
        },
    })
}

fn get_packet_id(attrs: &[Attribute]) -> syn::Result<Option<(u8, u16)>> {
    let Some(attr) = attrs.iter().find(|a| a.path().is_ident("Id")) else {
        return Ok(None);
    };
    let syn::Meta::List(list) = &attr.meta else {
        return Err(syn::Error::new(
            attr.span(),
            "Invalid syntax \nPerhaps you ment Id(id, subid)?",
        ));
    };

    let attrs: AttributeList = list.parse_args()?;
    if attrs.fields.len() != 2 {
        return Err(syn::Error::new(attr.span(), "Invalid number of arguments"));
    }
    let id = attrs.fields[0].base10_parse()?;
    let subid = attrs.fields[1].base10_parse()?;
    Ok(Some((id, subid)))
}

fn get_magic(attrs: &[Attribute]) -> syn::Result<Option<(u32, u32)>> {
    let Some(attr) = attrs.iter().find(|a| a.path().is_ident("Magic")) else {
        return Ok(None);
    };
    let syn::Meta::List(list) = &attr.meta else {
        return Err(syn::Error::new(
            attr.span(),
            "Invalid syntax \nPerhaps you ment Magic(xor, sub)?",
        ));
    };

    let attrs: AttributeList = list.parse_args()?;
    if attrs.fields.len() != 2 {
        return Err(syn::Error::new(attr.span(), "Invalid number of arguments"));
    }
    let xor = attrs.fields[0].base10_parse()?;
    let sub = attrs.fields[1].base10_parse()?;
    Ok(Some((xor, sub)))
}

fn get_flags(attrs: &[Attribute]) -> syn::Result<TokenStream> {
    let Some(attr) = attrs.iter().find(|a| a.path().is_ident("Flags")) else {
        return Ok(quote! {Flags::default()});
    };
    let syn::Meta::List(list) = &attr.meta else {
        return Err(syn::Error::new(
            attr.span(),
            "Invalid syntax \nPerhaps you ment Flags(..)?",
        ));
    };

    let attrs = &list.tokens;
    Ok(quote! {#attrs})
}

#[derive(Debug, Default, Clone)]
struct Field {
    name: String,
    field_type: FieldType,
    only_on: Option<PacketType>,
    not_on: Option<PacketType>,
    seek: i64,
    seek_after: i64,
    _no_seek: bool,
}

#[derive(Debug, Clone)]
struct FieldRead {
    name: String,
    field_data: FieldData,
}

#[derive(Debug, Default, Clone)]
enum FieldType {
    #[default]
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    I128,
    U128,
    F16,
    F32,
    F64,
    String,
    FixedString(u64),
    AsciiString,
    FixedAsciiString(u64),
    Ipv4,
    Duration {
        is_pso_time: bool,
    },
    Vec {
        size_type: Option<Size>,
        inner_type: Box<FieldType>,
    },
    FixedVec {
        size: u64,
        inner_type: Box<FieldType>,
    },
    ConstU16(u16),
    Struct(Box<PacketStructDef>),
    Unknown {
        name: String,
    },
}

#[derive(Clone)]
enum FieldData {
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    F16(half::f16),
    F32(f32),
    F64(f64),
    String(String),
    AsciiString(AsciiString),
    Ipv4(Ipv4Addr),
    Duration(Duration),
    Vec(Vec<FieldData>),
    Struct(Box<PacketStruct>),
}

impl Field {
    fn to_tokenstream(&self) -> Result<TokenStream, Box<dyn std::error::Error>> {
        let mut other_funcs = TokenStream::new();
        let type_ts = match &self.field_type {
            FieldType::I8 => quote!(i8),
            FieldType::U8 => quote!(u8),
            FieldType::I16 => quote!(i16),
            FieldType::U16 => quote!(u16),
            FieldType::I32 => quote!(i32),
            FieldType::U32 => quote!(u32),
            FieldType::I64 => quote!(i64),
            FieldType::U64 => quote!(u64),
            FieldType::I128 => quote!(i128),
            FieldType::U128 => quote!(u128),
            FieldType::F16 => quote!(f16),
            FieldType::F32 => quote!(f32),
            FieldType::F64 => quote!(f64),
            FieldType::String => quote!(String),
            FieldType::FixedString(len) => {
                other_funcs.extend(quote! {#[FixedLen(#len)]});
                quote! {String}
            }
            FieldType::AsciiString => quote!(AsciiString),
            FieldType::FixedAsciiString(len) => {
                other_funcs.extend(quote! {#[FixedLen(#len)]});
                quote! {AsciiString}
            }
            FieldType::Ipv4 => quote! {Ipv4Addr},
            FieldType::Duration { is_pso_time } => {
                if *is_pso_time {
                    other_funcs.extend(quote! {#[PSOTime]});
                }
                quote! {Duration}
            }
            FieldType::Vec {
                size_type,
                inner_type,
            } => {
                match size_type {
                    Some(Size::U16) => other_funcs.extend(quote! {#[Len_u16]}),
                    Some(Size::U32) => other_funcs.extend(quote! {#[Len_u32]}),
                    None => {}
                }
                let inner_type = inner_type.type_to_tokenstream()?;
                quote! {Vec<#inner_type>}
            }
            FieldType::FixedVec { size, inner_type } => {
                other_funcs.extend(quote! {#[FixedLen(#size)]});
                let inner_type = inner_type.type_to_tokenstream()?;
                quote! {Vec<#inner_type>}
            }
            FieldType::ConstU16(val) => return Ok(quote! {#[Const_u16(#val)]}),
            FieldType::Struct(s) => {
                let name = s.name.parse::<TokenStream>()?;
                quote! {#name}
            }
            FieldType::Unknown { name } => {
                let name = name.parse::<TokenStream>()?;
                quote! {#name}
            }
        };
        if self.seek != 0 {
            let val = self.seek;
            other_funcs.extend(quote! {#[Seek(#val)]})
        }
        if self.seek_after != 0 {
            let val = self.seek_after;
            other_funcs.extend(quote! {#[SeekAfter(#val)]})
        }
        other_funcs.extend(match self.only_on {
            Some(PacketType::NA) => quote! {#[OnlyOn(PacketType::NA)]},
            Some(PacketType::NGS) => quote! {#[OnlyOn(PacketType::NGS)]},
            Some(PacketType::JP) => quote! {#[OnlyOn(PacketType::JP)]},
            Some(PacketType::Vita) => quote! {#[OnlyOn(PacketType::Vita)]},
            Some(PacketType::Classic) => quote! {#[OnlyOn(PacketType::Classic)]},
            _ => quote! {},
        });
        other_funcs.extend(match self.not_on {
            Some(PacketType::NA) => quote! {#[NotOn(PacketType::NA)]},
            Some(PacketType::NGS) => quote! {#[NotOn(PacketType::NGS)]},
            Some(PacketType::JP) => quote! {#[NotOn(PacketType::JP)]},
            Some(PacketType::Vita) => quote! {#[NotOn(PacketType::Vita)]},
            Some(PacketType::Classic) => quote! {#[NotOn(PacketType::Classic)]},
            _ => quote! {},
        });
        let name = self.name.parse::<TokenStream>()?;
        Ok(quote! {
            #other_funcs
            pub #name: #type_ts,
        })
    }
    fn read(
        &self,
        data: &mut (impl Read + Seek),
        xor: u32,
        sub: u32,
    ) -> Result<FieldRead, PacketError> {
        Ok(FieldRead {
            name: self.name.clone(),
            field_data: self.field_type.read(data, xor, sub).map_err(|e| {
                PacketError::FieldError {
                    packet_name: "Dynamic packet",
                    // THIS IS UNSAFE! This *should* live as long as self, but DEFINITELY not 'static
                    field_name: unsafe { std::mem::transmute::<&str, &'static str>(self.name.as_str()) },
                    error: e,
                }
            })?,
        })
    }
}

impl FieldType {
    fn type_to_tokenstream(&self) -> Result<TokenStream, Box<dyn std::error::Error>> {
        let type_ts = match &self {
            FieldType::I8 => quote!(i8),
            FieldType::U8 => quote!(u8),
            FieldType::I16 => quote!(i16),
            FieldType::U16 => quote!(u16),
            FieldType::I32 => quote!(i32),
            FieldType::U32 => quote!(u32),
            FieldType::I64 => quote!(i64),
            FieldType::U64 => quote!(u64),
            FieldType::I128 => quote!(i128),
            FieldType::U128 => quote!(u128),
            FieldType::F16 => quote!(f16),
            FieldType::F32 => quote!(f32),
            FieldType::F64 => quote!(f64),
            FieldType::Ipv4 => quote! {Ipv4Addr},
            FieldType::Duration { .. } => {
                quote! {Duration}
            }
            FieldType::Struct(s) => {
                let name = s.name.parse::<TokenStream>()?;
                quote! {#name}
            }
            FieldType::Unknown { name } => {
                let name = name.parse::<TokenStream>()?;
                quote! {#name}
            }
            _ => quote! {},
        };
        Ok(type_ts)
    }
    fn read(
        &self,
        data: &mut (impl Read + Seek),
        xor: u32,
        sub: u32,
    ) -> Result<FieldData, std::io::Error> {
        Ok(match self {
            FieldType::I8 => {
                let mut val = 0;
                data.read_exact(std::slice::from_mut(&mut val))?;
                FieldData::I8(val as _)
            }
            FieldType::U8 => {
                let mut val = 0;
                data.read_exact(std::slice::from_mut(&mut val))?;
                FieldData::U8(val as _)
            }
            FieldType::I16 => {
                let mut val = [0; 2];
                data.read_exact(&mut val)?;
                FieldData::I16(i16::from_le_bytes(val))
            }
            FieldType::U16 => {
                let mut val = [0; 2];
                data.read_exact(&mut val)?;
                FieldData::U16(u16::from_le_bytes(val))
            }
            FieldType::I32 => {
                let mut val = [0; 4];
                data.read_exact(&mut val)?;
                FieldData::I32(i32::from_le_bytes(val))
            }
            FieldType::U32 => {
                let mut val = [0; 4];
                data.read_exact(&mut val)?;
                FieldData::U32(u32::from_le_bytes(val))
            }
            FieldType::I64 => {
                let mut val = [0; 8];
                data.read_exact(&mut val)?;
                FieldData::I64(i64::from_le_bytes(val))
            }
            FieldType::U64 => {
                let mut val = [0; 8];
                data.read_exact(&mut val)?;
                FieldData::U64(u64::from_le_bytes(val))
            }
            FieldType::I128 => {
                let mut val = [0; 16];
                data.read_exact(&mut val)?;
                FieldData::I128(i128::from_le_bytes(val))
            }
            FieldType::U128 => {
                let mut val = [0; 16];
                data.read_exact(&mut val)?;
                FieldData::U128(u128::from_le_bytes(val))
            }
            FieldType::F16 => {
                let mut val = [0; 2];
                data.read_exact(&mut val)?;
                FieldData::F16(half::f16::from_le_bytes(val))
            }
            FieldType::F32 => {
                let mut val = [0; 4];
                data.read_exact(&mut val)?;
                FieldData::F32(f32::from_le_bytes(val))
            }
            FieldType::F64 => {
                let mut val = [0; 8];
                data.read_exact(&mut val)?;
                FieldData::F64(f64::from_le_bytes(val))
            }
            FieldType::String => FieldData::String(String::read_variable(data, sub, xor)?),
            FieldType::FixedString(l) => FieldData::String(String::read(data, *l)?),
            FieldType::AsciiString => {
                FieldData::AsciiString(AsciiString::read_variable(data, sub, xor)?)
            }
            FieldType::FixedAsciiString(l) => FieldData::AsciiString(AsciiString::read(data, *l)?),
            FieldType::Ipv4 => {
                let mut val = [0; 4];
                data.read_exact(&mut val)?;
                FieldData::Ipv4(Ipv4Addr::from(val))
            }
            FieldType::Duration { is_pso_time } => FieldData::Duration(if *is_pso_time {
                let mut val = [0; 8];
                data.read_exact(&mut val)?;
                Duration::from_millis(u64::from_le_bytes(val) - 0x0295_E964_8864)
            } else {
                let mut val = [0; 4];
                data.read_exact(&mut val)?;
                Duration::from_secs(u32::from_le_bytes(val) as u64)
            }),
            FieldType::Vec {
                size_type,
                inner_type,
            } => {
                let len = match size_type {
                    Some(Size::U16) => {
                        let mut val = [0; 2];
                        data.read_exact(&mut val)?;
                        u16::from_le_bytes(val) as u32
                    }
                    Some(Size::U32) => {
                        let mut val = [0; 4];
                        data.read_exact(&mut val)?;
                        u32::from_le_bytes(val)
                    }
                    None => {
                        let mut val = [0; 4];
                        data.read_exact(&mut val)?;
                        (u32::from_le_bytes(val) ^ xor) - sub
                    }
                };
                let mut fields = vec![];
                for _ in 0..len {
                    fields.push(inner_type.read(data, xor, sub)?);
                }
                FieldData::Vec(fields)
            }
            FieldType::FixedVec { size, inner_type } => {
                let mut fields = vec![];
                for _ in 0..*size {
                    fields.push(inner_type.read(data, xor, sub)?);
                }
                FieldData::Vec(fields)
            }
            FieldType::ConstU16(_) => todo!(),
            FieldType::Struct(s) => FieldData::Struct(Box::new(
                s.read(data, xor, sub).map_err(std::io::Error::other)?,
            )),
            FieldType::Unknown { name } => {
                return Err(std::io::Error::other(format!("Unknown packet: {name}")))
            }
        })
    }
    fn populate_struct(&mut self, structs: &[PacketStructDef]) {
        match self {
            FieldType::Unknown { ref name } => {
                let struct_def = structs.iter().find(|s| s.name == *name).cloned();
                if let Some(mut def) = struct_def {
                    def.populate_structs(structs);
                    *self = FieldType::Struct(def.into());
                }
            }
            FieldType::Vec { inner_type, .. } => {
                inner_type.populate_struct(structs);
            }
            FieldType::FixedVec { inner_type, .. } => {
                inner_type.populate_struct(structs);
            }
            _ => {}
        }
    }
}

impl std::fmt::Debug for FieldData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::I8(x) => x.fmt(f),
            Self::U8(x) => x.fmt(f),
            Self::I16(x) => x.fmt(f),
            Self::U16(x) => x.fmt(f),
            Self::I32(x) => x.fmt(f),
            Self::U32(x) => x.fmt(f),
            Self::I64(x) => x.fmt(f),
            Self::U64(x) => x.fmt(f),
            Self::I128(x) => x.fmt(f),
            Self::U128(x) => x.fmt(f),
            Self::F16(x) => x.fmt(f),
            Self::F32(x) => x.fmt(f),
            Self::F64(x) => x.fmt(f),
            Self::String(x) => x.fmt(f),
            Self::AsciiString(x) => x.fmt(f),
            Self::Ipv4(x) => x.fmt(f),
            Self::Duration(x) => x.fmt(f),
            Self::Vec(x) => x.fmt(f),
            Self::Struct(x) => x.fmt(f),
        }
    }
}

impl std::fmt::Debug for PacketStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct(&self.name);
        for field in &self.fields {
            f.field(&field.name, &field.field_data);
        }
        f.finish()
    }
}

#[derive(Default)]
struct Settings {
    is_psotime: bool,
    seek: i64,
    seek_after: i64,
    str_type: StringType,
    is_default: bool,
    to_skip: bool,
    only_on: Option<PacketType>,
    not_on: Option<PacketType>,
    fixed_len: u32,
    len_size: Option<Size>,
    consts: Vec<FieldType>,
}

fn get_attrs(set: &mut Settings, string: &str, list: Option<&MetaList>) -> syn::Result<()> {
    match string {
        "Read_default" => set.is_default = true,
        "PSOTime" => set.is_psotime = true,
        "Skip" => set.to_skip = true,
        "OnlyOn" => {
            let Some(attrs) = list.map(|l| l.tokens.clone()) else {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "Invalid syntax \nPerhaps you ment OnlyOn(..)?",
                ));
            };
            set.only_on = match attrs.to_string().as_str() {
                "NGS" => Some(PacketType::NGS),
                "Classic" => Some(PacketType::Classic),
                "NA" => Some(PacketType::NA),
                "JP" => Some(PacketType::JP),
                "Vita" => Some(PacketType::Vita),
                _ => None,
            };
        }
        "NotOn" => {
            let Some(attrs) = list.map(|l| l.tokens.clone()) else {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "Invalid syntax \nPerhaps you ment NotOn(..)?",
                ));
            };
            set.not_on = match attrs.to_string().as_str() {
                "NGS" => Some(PacketType::NGS),
                "Classic" => Some(PacketType::Classic),
                "NA" => Some(PacketType::NA),
                "JP" => Some(PacketType::JP),
                "Vita" => Some(PacketType::Vita),
                _ => None,
            };
        }
        "Seek" => {
            if let Some(arg) = &list {
                set.seek = arg.parse_args::<LitInt>()?.base10_parse()?;
            }
        }
        "SeekAfter" => {
            if let Some(arg) = &list {
                set.seek_after = arg.parse_args::<LitInt>()?.base10_parse()?;
            }
        }
        "FixedLen" => {
            if let Some(arg) = &list {
                set.fixed_len = arg.parse_args::<LitInt>()?.base10_parse()?;
                set.str_type = StringType::Fixed(set.fixed_len as u64);
            }
        }
        "Const_u16" => {
            if let Some(arg) = &list {
                let num: u16 = arg.parse_args::<LitInt>()?.base10_parse()?;
                set.consts.push(FieldType::ConstU16(num));
            }
        }
        "Len_u16" => {
            set.len_size = Some(Size::U16);
        }
        "Len_u32" => {
            set.len_size = Some(Size::U32);
        }
        _ => {}
    }
    Ok(())
}

#[derive(Default)]
enum StringType {
    #[default]
    Unknown,
    // len
    Fixed(u64),
}

#[derive(Debug, Clone, Copy)]
enum Size {
    U16,
    U32,
}

struct AttributeList {
    fields: Punctuated<LitInt, Token![,]>,
}

impl syn::parse::Parse for AttributeList {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        Ok(Self {
            fields: Punctuated::parse_separated_nonempty(input)?,
        })
    }
}
