//! Built-in standard VBA P-code opcode definitions, identifier table extraction,
//! and complete P-code disassembly engine.
//!
//! This module implements the standard opcode tables (VBA6/VBA7, 32-bit and 64-bit),
//! identifier extraction from the `_VBA_PROJECT` stream, and accurate instruction disassembly.

use crate::compiled::{
    PCodeInstructionSchema, PCodeOpcodeDefinition, PCodeOperandEncoding, inspect_vba7_line_map,
};

/// The internal keywords, types, and operator names present in the VBA runtime engine.
pub static INTERNAL_NAMES: &[&str] = &[
    "<crash>",
    "0",
    "Abs",
    "Access",
    "AddressOf",
    "Alias",
    "And",
    "Any",
    "Append",
    "Array",
    "As",
    "Assert",
    "B",
    "Base",
    "BF",
    "Binary",
    "Boolean",
    "ByRef",
    "Byte",
    "ByVal",
    "Call",
    "Case",
    "CBool",
    "CByte",
    "CCur",
    "CDate",
    "CDec",
    "CDbl",
    "CDecl",
    "ChDir",
    "CInt",
    "Circle",
    "CLng",
    "Close",
    "Compare",
    "Const",
    "CSng",
    "CStr",
    "CurDir",
    "CurDir$",
    "CVar",
    "CVDate",
    "CVErr",
    "Currency",
    "Database",
    "Date",
    "Date$",
    "Debug",
    "Decimal",
    "Declare",
    "DefBool",
    "DefByte",
    "DefCur",
    "DefDate",
    "DefDec",
    "DefDbl",
    "DefInt",
    "DefLng",
    "DefObj",
    "DefSng",
    "DefStr",
    "DefVar",
    "Dim",
    "Dir",
    "Dir$",
    "Do",
    "DoEvents",
    "Double",
    "Each",
    "Else",
    "ElseIf",
    "Empty",
    "End",
    "EndIf",
    "Enum",
    "Eqv",
    "Erase",
    "Error",
    "Error$",
    "Event",
    "WithEvents",
    "Explicit",
    "F",
    "False",
    "Fix",
    "For",
    "Format",
    "Format$",
    "FreeFile",
    "Friend",
    "Function",
    "Get",
    "Global",
    "Go",
    "GoSub",
    "Goto",
    "If",
    "Imp",
    "Implements",
    "In",
    "Input",
    "Input$",
    "InputB",
    "InputB",
    "InStr",
    "InputB$",
    "Int",
    "InStrB",
    "Is",
    "Integer",
    "Left",
    "LBound",
    "LenB",
    "Len",
    "Lib",
    "Let",
    "Line",
    "Like",
    "Load",
    "Local",
    "Lock",
    "Long",
    "Loop",
    "LSet",
    "Me",
    "Mid",
    "Mid$",
    "MidB",
    "MidB$",
    "Mod",
    "Module",
    "Name",
    "New",
    "Next",
    "Not",
    "Nothing",
    "Null",
    "Object",
    "On",
    "Open",
    "Option",
    "Optional",
    "Or",
    "Output",
    "ParamArray",
    "Preserve",
    "Print",
    "Private",
    "Property",
    "PSet",
    "Public",
    "Put",
    "RaiseEvent",
    "Random",
    "Randomize",
    "Read",
    "ReDim",
    "Rem",
    "Resume",
    "Return",
    "RGB",
    "RSet",
    "Scale",
    "Seek",
    "Select",
    "Set",
    "Sgn",
    "Shared",
    "Single",
    "Spc",
    "Static",
    "Step",
    "Stop",
    "StrComp",
    "String",
    "String$",
    "Sub",
    "Tab",
    "Text",
    "Then",
    "To",
    "True",
    "Type",
    "TypeOf",
    "UBound",
    "Unload",
    "Unlock",
    "Unknown",
    "Until",
    "Variant",
    "WEnd",
    "While",
    "Width",
    "With",
    "Write",
    "Xor",
    "#Const",
    "#Else",
    "#ElseIf",
    "#End",
    "#If",
    "Attribute",
    "VB_Base",
    "VB_Control",
    "VB_Creatable",
    "VB_Customizable",
    "VB_Description",
    "VB_Exposed",
    "VB_Ext_Key",
    "VB_HelpID",
    "VB_Invoke_Func",
    "VB_Invoke_Property",
    "VB_Invoke_PropertyPut",
    "VB_Invoke_PropertyPutRef",
    "VB_MemberFlags",
    "VB_Name",
    "VB_PredecraredID",
    "VB_ProcData",
    "VB_TemplateDerived",
    "VB_VarDescription",
    "VB_VarHelpID",
    "VB_VarMemberFlags",
    "VB_VarProcData",
    "VB_UserMemID",
    "VB_VarUserMemID",
    "VB_GlobalNameSpace",
    ",",
    ".",
    "\"",
    "_",
    "!",
    "#",
    "&",
    "'",
    "(",
    ")",
    "*",
    "+",
    "-",
    " /",
    ":",
    ";",
    "<",
    "<=",
    "<>",
    "=",
    "=<",
    "=>",
    ">",
    "><",
    ">=",
    "?",
    "\\",
    "^",
    ":=",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeArgKind {
    Name,
    HexWord,
    Imp,
    Func,
    Var,
    Rec,
    TypeDesc,
    Context,
}

#[derive(Clone, Copy, Debug)]
pub struct PCodeOpcodeMeta {
    pub opcode: u16,
    pub mnemonic: &'static str,
    pub args: &'static [PCodeArgKind],
    pub varg: bool,
}

macro_rules! op {
    ($op:expr, $mne:expr, [$($arg:ident),*], $varg:expr) => {
        PCodeOpcodeMeta {
            opcode: $op,
            mnemonic: $mne,
            args: &[$($arg),*],
            varg: $varg,
        }
    };
}

use PCodeArgKind::{Context as ContextArg, Func, HexWord, Imp, Name, Rec, TypeDesc, Var};

/// Standard VBA7 opcode metadata table (264 opcodes, indices 0..=263).
pub static STANDARD_VBA7_OPCODES: &[PCodeOpcodeMeta] = &[
    op!(0, "Imp", [], false),
    op!(1, "Eqv", [], false),
    op!(2, "Xor", [], false),
    op!(3, "Or", [], false),
    op!(4, "And", [], false),
    op!(5, "Eq", [], false),
    op!(6, "Ne", [], false),
    op!(7, "Le", [], false),
    op!(8, "Ge", [], false),
    op!(9, "Lt", [], false),
    op!(10, "Gt", [], false),
    op!(11, "Add", [], false),
    op!(12, "Sub", [], false),
    op!(13, "Mod", [], false),
    op!(14, "IDiv", [], false),
    op!(15, "Mul", [], false),
    op!(16, "Div", [], false),
    op!(17, "Concat", [], false),
    op!(18, "Like", [], false),
    op!(19, "Pwr", [], false),
    op!(20, "Is", [], false),
    op!(21, "Not", [], false),
    op!(22, "UMi", [], false),
    op!(23, "FnAbs", [], false),
    op!(24, "FnFix", [], false),
    op!(25, "FnInt", [], false),
    op!(26, "FnSgn", [], false),
    op!(27, "FnLen", [], false),
    op!(28, "FnLenB", [], false),
    op!(29, "Paren", [], false),
    op!(30, "Sharp", [], false),
    op!(31, "LdLHS", [Name], false),
    op!(32, "Ld", [Name], false),
    op!(33, "MemLd", [Name], false),
    op!(34, "DictLd", [Name], false),
    op!(35, "IndexLd", [HexWord], false),
    op!(36, "ArgsLd", [Name, HexWord], false),
    op!(37, "ArgsMemLd", [Name, HexWord], false),
    op!(38, "ArgsDictLd", [Name, HexWord], false),
    op!(39, "St", [Name], false),
    op!(40, "MemSt", [Name], false),
    op!(41, "DictSt", [Name], false),
    op!(42, "IndexSt", [HexWord], false),
    op!(43, "ArgsSt", [Name, HexWord], false),
    op!(44, "ArgsMemSt", [Name, HexWord], false),
    op!(45, "ArgsDictSt", [Name, HexWord], false),
    op!(46, "Set", [Name], false),
    op!(47, "Memset", [Name], false),
    op!(48, "Dictset", [Name], false),
    op!(49, "Indexset", [HexWord], false),
    op!(50, "ArgsSet", [Name, HexWord], false),
    op!(51, "ArgsMemSet", [Name, HexWord], false),
    op!(52, "ArgsDictSet", [Name, HexWord], false),
    op!(53, "MemLdWith", [Name], false),
    op!(54, "DictLdWith", [Name], false),
    op!(55, "ArgsMemLdWith", [Name, HexWord], false),
    op!(56, "ArgsDictLdWith", [Name, HexWord], false),
    op!(57, "MemStWith", [Name], false),
    op!(58, "DictStWith", [Name], false),
    op!(59, "ArgsMemStWith", [Name, HexWord], false),
    op!(60, "ArgsDictStWith", [Name, HexWord], false),
    op!(61, "MemSetWith", [Name], false),
    op!(62, "DictSetWith", [Name], false),
    op!(63, "ArgsMemSetWith", [Name, HexWord], false),
    op!(64, "ArgsDictSetWith", [Name, HexWord], false),
    op!(65, "ArgsCall", [Name, HexWord], false),
    op!(66, "ArgsMemCall", [Name, HexWord], false),
    op!(67, "ArgsMemCallWith", [Name, HexWord], false),
    op!(68, "ArgsArray", [Name, HexWord], false),
    op!(69, "Assert", [], false),
    op!(70, "BoS", [HexWord], false),
    op!(71, "BoSImplicit", [], false),
    op!(72, "BoL", [], false),
    op!(73, "LdAddressOf", [Name], false),
    op!(74, "MemAddressOf", [Name], false),
    op!(75, "Case", [], false),
    op!(76, "CaseTo", [], false),
    op!(77, "CaseGt", [], false),
    op!(78, "CaseLt", [], false),
    op!(79, "CaseGe", [], false),
    op!(80, "CaseLe", [], false),
    op!(81, "CaseNe", [], false),
    op!(82, "CaseEq", [], false),
    op!(83, "CaseElse", [], false),
    op!(84, "CaseDone", [], false),
    op!(85, "Circle", [HexWord], false),
    op!(86, "Close", [HexWord], false),
    op!(87, "CloseAll", [], false),
    op!(88, "Coerce", [], false),
    op!(89, "CoerceVar", [], false),
    op!(90, "Context", [ContextArg], false),
    op!(91, "Debug", [], false),
    op!(92, "DefType", [HexWord, HexWord], false),
    op!(93, "Dim", [], false),
    op!(94, "DimImplicit", [], false),
    op!(95, "Do", [], false),
    op!(96, "DoEvents", [], false),
    op!(97, "DoUnitil", [], false),
    op!(98, "DoWhile", [], false),
    op!(99, "Else", [], false),
    op!(100, "ElseBlock", [], false),
    op!(101, "ElseIfBlock", [], false),
    op!(102, "ElseIfTypeBlock", [Imp], false),
    op!(103, "End", [], false),
    op!(104, "EndContext", [], false),
    op!(105, "EndFunc", [], false),
    op!(106, "EndIf", [], false),
    op!(107, "EndIfBlock", [], false),
    op!(108, "EndImmediate", [], false),
    op!(109, "EndProp", [], false),
    op!(110, "EndSelect", [], false),
    op!(111, "EndSub", [], false),
    op!(112, "EndType", [], false),
    op!(113, "EndWith", [], false),
    op!(114, "Erase", [HexWord], false),
    op!(115, "Error", [], false),
    op!(116, "EventDecl", [Func], false),
    op!(117, "RaiseEvent", [Name, HexWord], false),
    op!(118, "ArgsMemRaiseEvent", [Name, HexWord], false),
    op!(119, "ArgsMemRaiseEventWith", [Name, HexWord], false),
    op!(120, "ExitDo", [], false),
    op!(121, "ExitFor", [], false),
    op!(122, "ExitFunc", [], false),
    op!(123, "ExitProp", [], false),
    op!(124, "ExitSub", [], false),
    op!(125, "FnCurDir", [], false),
    op!(126, "FnDir", [], false),
    op!(127, "Empty0", [], false),
    op!(128, "Empty1", [], false),
    op!(129, "FnError", [], false),
    op!(130, "FnFormat", [], false),
    op!(131, "FnFreeFile", [], false),
    op!(132, "FnInStr", [], false),
    op!(133, "FnInStr3", [], false),
    op!(134, "FnInStr4", [], false),
    op!(135, "FnInStrB", [], false),
    op!(136, "FnInStrB3", [], false),
    op!(137, "FnInStrB4", [], false),
    op!(138, "FnLBound", [HexWord], false),
    op!(139, "FnMid", [], false),
    op!(140, "FnMidB", [], false),
    op!(141, "FnStrComp", [], false),
    op!(142, "FnStrComp3", [], false),
    op!(143, "FnStringVar", [], false),
    op!(144, "FnStringStr", [], false),
    op!(145, "FnUBound", [HexWord], false),
    op!(146, "For", [], false),
    op!(147, "ForEach", [], false),
    op!(148, "ForEachAs", [Imp], false),
    op!(149, "ForStep", [], false),
    op!(150, "FuncDefn", [Func], false),
    op!(151, "FuncDefnSave", [Func], false),
    op!(152, "GetRec", [], false),
    op!(153, "GoSub", [Name], false),
    op!(154, "GoTo", [Name], false),
    op!(155, "If", [], false),
    op!(156, "IfBlock", [], false),
    op!(157, "TypeOf", [Imp], false),
    op!(158, "IfTypeBlock", [Imp], false),
    op!(
        159,
        "Implements",
        [HexWord, HexWord, HexWord, HexWord],
        false
    ),
    op!(160, "Input", [], false),
    op!(161, "InputDone", [], false),
    op!(162, "InputItem", [], false),
    op!(163, "Label", [Name], false),
    op!(164, "Let", [], false),
    op!(165, "Line", [HexWord], false),
    op!(166, "LineCont", [], true),
    op!(167, "LineInput", [], false),
    op!(168, "LineNum", [Name], false),
    op!(169, "LitCy", [HexWord, HexWord, HexWord, HexWord], false),
    op!(170, "LitDate", [HexWord, HexWord, HexWord, HexWord], false),
    op!(171, "LitDefault", [], false),
    op!(172, "LitDI2", [HexWord], false),
    op!(173, "LitDI4", [HexWord, HexWord], false),
    op!(174, "LitDI8", [HexWord, HexWord, HexWord, HexWord], false),
    op!(175, "LitHI2", [HexWord], false),
    op!(176, "LitHI4", [HexWord, HexWord], false),
    op!(177, "LitHI8", [HexWord, HexWord, HexWord, HexWord], false),
    op!(178, "LitNothing", [], false),
    op!(179, "LitOI2", [HexWord], false),
    op!(180, "LitOI4", [HexWord, HexWord], false),
    op!(181, "LitOI8", [HexWord, HexWord, HexWord, HexWord], false),
    op!(182, "LitR4", [HexWord, HexWord], false),
    op!(183, "LitR8", [HexWord, HexWord, HexWord, HexWord], false),
    op!(184, "LitSmallI2", [], false),
    op!(185, "LitStr", [], true),
    op!(186, "LitVarSpecial", [], false),
    op!(187, "Lock", [], false),
    op!(188, "Loop", [], false),
    op!(189, "LoopUntil", [], false),
    op!(190, "LoopWhile", [], false),
    op!(191, "LSet", [], false),
    op!(192, "Me", [], false),
    op!(193, "MeImplicit", [], false),
    op!(194, "MemRedim", [Name, HexWord, TypeDesc], false),
    op!(195, "MemRedimWith", [Name, HexWord, TypeDesc], false),
    op!(196, "MemRedimAs", [Name, HexWord, TypeDesc], false),
    op!(197, "MemRedimAsWith", [Name, HexWord, TypeDesc], false),
    op!(198, "Mid", [], false),
    op!(199, "MidB", [], false),
    op!(200, "Name", [], false),
    op!(201, "New", [Imp], false),
    op!(202, "Next", [], false),
    op!(203, "NextVar", [], false),
    op!(204, "OnError", [Name], false),
    op!(205, "OnGosub", [], true),
    op!(206, "OnGoto", [], true),
    op!(207, "Open", [HexWord], false),
    op!(208, "Option", [], false),
    op!(209, "OptionBase", [], false),
    op!(210, "ParamByVal", [], false),
    op!(211, "ParamOmitted", [], false),
    op!(212, "ParamNamed", [Name], false),
    op!(213, "PrintChan", [], false),
    op!(214, "PrintComma", [], false),
    op!(215, "PrintEoS", [], false),
    op!(216, "PrintItemComma", [], false),
    op!(217, "PrintItemNL", [], false),
    op!(218, "PrintItemSemi", [], false),
    op!(219, "PrintNL", [], false),
    op!(220, "PrintObj", [], false),
    op!(221, "PrintSemi", [], false),
    op!(222, "PrintSpc", [], false),
    op!(223, "PrintTab", [], false),
    op!(224, "PrintTabComma", [], false),
    op!(225, "PSet", [HexWord], false),
    op!(226, "PutRec", [], false),
    op!(227, "QuoteRem", [HexWord], true),
    op!(228, "Redim", [Name, HexWord, TypeDesc], false),
    op!(229, "RedimAs", [Name, HexWord, TypeDesc], false),
    op!(230, "Reparse", [], true),
    op!(231, "Rem", [], true),
    op!(232, "Resume", [Name], false),
    op!(233, "Return", [], false),
    op!(234, "RSet", [], false),
    op!(235, "Scale", [HexWord], false),
    op!(236, "Seek", [], false),
    op!(237, "SelectCase", [], false),
    op!(238, "SelectIs", [Imp], false),
    op!(239, "SelectType", [], false),
    op!(240, "SetStmt", [], false),
    op!(241, "Stack", [HexWord, HexWord], false),
    op!(242, "Stop", [], false),
    op!(243, "Type", [Rec], false),
    op!(244, "Unlock", [], false),
    op!(245, "VarDefn", [Var], false),
    op!(246, "Wend", [], false),
    op!(247, "While", [], false),
    op!(248, "With", [], false),
    op!(249, "WriteChan", [], false),
    op!(250, "ConstFuncExpr", [], false),
    op!(251, "LbConst", [Name], false),
    op!(252, "LbIf", [], false),
    op!(253, "LbElse", [], false),
    op!(254, "LbElseIf", [], false),
    op!(255, "LbEndIf", [], false),
    op!(256, "LbMark", [], false),
    op!(257, "EndForVariable", [], false),
    op!(258, "StartForVariable", [], false),
    op!(259, "NewRedim", [], false),
    op!(260, "StartWithExpr", [], false),
    op!(261, "SetOrSt", [Name], false),
    op!(262, "EndEnum", [], false),
    op!(263, "Illegal", [], false),
];

/// Translate an observed opcode from a specific VBA version into standard VBA7 opcode indexing.
pub fn translate_opcode(opcode: u16, vba_ver: u16, is_64bit: bool) -> u16 {
    if vba_ver == 3 {
        if opcode <= 67 {
            opcode
        } else if opcode <= 70 {
            opcode + 2
        } else if opcode <= 111 {
            opcode + 4
        } else if opcode <= 150 {
            opcode + 8
        } else if opcode <= 164 {
            opcode + 9
        } else if opcode <= 166 {
            opcode + 10
        } else if opcode <= 169 {
            opcode + 11
        } else if opcode <= 238 {
            opcode + 12
        } else {
            opcode + 24
        }
    } else if vba_ver == 5 {
        if opcode <= 68 {
            opcode
        } else if opcode <= 71 {
            opcode + 1
        } else if opcode <= 112 {
            opcode + 3
        } else if opcode <= 151 {
            opcode + 7
        } else if opcode <= 165 {
            opcode + 8
        } else if opcode <= 167 {
            opcode + 9
        } else if opcode <= 170 {
            opcode + 10
        } else {
            opcode + 11
        }
    } else if !is_64bit {
        if opcode <= 173 {
            opcode
        } else if opcode <= 175 {
            opcode + 1
        } else if opcode <= 178 {
            opcode + 2
        } else {
            opcode + 3
        }
    } else {
        opcode
    }
}

/// Resolve an identifier or keyword by its 16-bit ID code.
pub fn get_id(mut id_code: u16, identifiers: &[String], vba_ver: u16, is_64bit: bool) -> String {
    let orig_code = id_code;
    id_code >>= 1;
    if id_code >= 0x100 {
        let mut idx = (id_code - 0x100) as usize;
        if vba_ver >= 7 {
            if idx >= 4 {
                idx -= 4;
            } else {
                idx = 0;
            }
            if is_64bit {
                if idx >= 3 {
                    idx -= 3;
                } else {
                    idx = 0;
                }
            }
            if idx > 0xBE {
                idx -= 1;
            }
        }
        if let Some(ident) = identifiers.get(idx) {
            return ident.clone();
        }
    } else {
        let mut idx = id_code as usize;
        if vba_ver >= 7 && idx >= 0xC3 {
            idx -= 1;
        }
        if let Some(&name) = INTERNAL_NAMES.get(idx) {
            return name.to_string();
        }
    }
    format!("id_{:04X}", orig_code)
}

/// Construct a standard `PCodeInstructionSchema` covering the complete VBA7 instruction set.
pub fn standard_vba7_instruction_schema(is_64bit: bool) -> PCodeInstructionSchema {
    let mut definitions = Vec::with_capacity(STANDARD_VBA7_OPCODES.len());
    for meta in STANDARD_VBA7_OPCODES {
        let mut operands = Vec::new();
        for &arg in meta.args {
            match arg {
                PCodeArgKind::Name | PCodeArgKind::HexWord | PCodeArgKind::Imp => {
                    operands.push(PCodeOperandEncoding::Word16);
                }
                PCodeArgKind::Func
                | PCodeArgKind::Var
                | PCodeArgKind::Rec
                | PCodeArgKind::TypeDesc => {
                    operands.push(PCodeOperandEncoding::DoubleWord32);
                }
                PCodeArgKind::Context => {
                    operands.push(PCodeOperandEncoding::DoubleWord32);
                    if is_64bit {
                        operands.push(PCodeOperandEncoding::DoubleWord32);
                    }
                }
            }
        }
        if meta.varg {
            operands.push(PCodeOperandEncoding::BytesPrefixedByWord {
                pad_odd_payload_to_even: true,
            });
        }
        definitions.push(PCodeOpcodeDefinition {
            opcode: meta.opcode,
            operation_type: None,
            mnemonic: meta.mnemonic.to_string(),
            operands,
        });
    }

    PCodeInstructionSchema {
        id: if is_64bit {
            "vba7-x64-standard".into()
        } else {
            "vba7-x86-standard".into()
        },
        opcode_mask: 0x03FF,
        opcode_shift: 0,
        operation_type_mask: 0xFC00,
        operation_type_shift: 10,
        definitions,
    }
}

/// Construct a standard `PCodeInstructionSchema` for VBA6.
pub fn standard_vba6_instruction_schema() -> PCodeInstructionSchema {
    let mut schema = standard_vba7_instruction_schema(false);
    schema.id = "vba6-standard".into();
    schema
}

/// Read little-endian 16-bit integer safely.
#[inline]
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 <= data.len() {
        Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    }
}

/// Read little-endian 32-bit integer safely.
#[inline]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= data.len() {
        Some(u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        None
    }
}

/// Skip structure helper following pcodedmp logic.
fn skip_structure(
    data: &[u8],
    mut offset: usize,
    is_dword_length: bool,
    elem_size: usize,
    check_minus_one: bool,
) -> Option<usize> {
    let (length, len_bytes) = if is_dword_length {
        let val = read_u32(data, offset)?;
        (val as usize, 4)
    } else {
        let val = read_u16(data, offset)?;
        (val as usize, 2)
    };
    offset += len_bytes;
    let skip = check_minus_one && (length == 0xFFFF || (is_dword_length && length == 0xFFFF_FFFF));
    if !skip {
        let bytes_to_skip = length.checked_mul(elem_size)?;
        offset = offset.checked_add(bytes_to_skip)?;
    }
    if offset <= data.len() {
        Some(offset)
    } else {
        None
    }
}

/// Parse identifier names from the `_VBA_PROJECT` stream data (starts with magic `0x61CC`).
pub fn parse_vba_project_identifiers(data: &[u8]) -> Result<Vec<String>, String> {
    if data.len() < 30 {
        return Err("VBA project stream too small for header".into());
    }
    let magic = read_u16(data, 0).ok_or("cannot read magic")?;
    if magic != 0x61CC {
        return Err(format!("invalid _VBA_PROJECT magic: 0x{:04X}", magic));
    }
    let version = read_u16(data, 2).ok_or("cannot read version")?;
    let unicode_ref =
        (version >= 0x5B && !matches!(version, 0x60 | 0x62 | 0x63)) || version == 0x4E;
    let unicode_name =
        (version >= 0x59 && !matches!(version, 0x60 | 0x62 | 0x63)) || version == 0x4E;
    let non_unicode_name =
        (version <= 0x59 && version != 0x4E) || (version > 0x5F && version < 0x6B);

    let mut offset = 0x1E;
    let num_refs = read_u16(data, offset).ok_or("cannot read numRefs")? as usize;
    if num_refs > 1024 {
        return Err("too many references in _VBA_PROJECT stream".into());
    }
    offset += 4; // skip numRefs + 2

    for _ in 0..num_refs {
        if offset + 2 > data.len() {
            return Err("truncated reference entries".into());
        }
        let ref_len = read_u16(data, offset).ok_or("cannot read refLen")? as usize;
        offset += 2;
        if ref_len == 0 {
            offset += 6;
        } else {
            let min_len = if unicode_ref { 5 } else { 3 };
            if ref_len < min_len {
                offset += ref_len;
            } else {
                let c_offset = if unicode_ref { offset + 4 } else { offset + 2 };
                let c = data.get(c_offset).copied().unwrap_or(0);
                offset += ref_len;
                if c == b'C' || c == b'D' {
                    offset = skip_structure(data, offset, false, 1, false)
                        .ok_or("failed skipping ref struct")?;
                }
            }
        }
        offset += 10;
        if offset + 2 > data.len() {
            break;
        }
        let word = read_u16(data, offset).unwrap_or(0);
        offset += 2;
        if word != 0 {
            offset =
                skip_structure(data, offset, false, 1, false).ok_or("failed skipping ref word")?;
            let w_len = read_u16(data, offset).unwrap_or(0) as usize;
            offset += 2;
            if w_len > 0 {
                offset += 2;
            }
            offset += w_len + 30;
        }
    }

    // Class / user forms table
    offset = skip_structure(data, offset, false, 2, false).ok_or("failed skipping class table")?;
    // Compile-time identifier-value pairs
    offset =
        skip_structure(data, offset, false, 4, false).ok_or("failed skipping compile pairs")?;
    offset += 2;
    // Typeinfo typeID
    offset = skip_structure(data, offset, false, 1, true).ok_or("failed skipping typeinfo")?;
    // Project description
    offset = skip_structure(data, offset, false, 1, true).ok_or("failed skipping desc")?;
    // Project help file name
    offset = skip_structure(data, offset, false, 1, true).ok_or("failed skipping help")?;
    offset += 0x64;

    if offset + 2 > data.len() {
        return Err("truncated before module descriptors".into());
    }
    let num_projects = read_u16(data, offset).ok_or("cannot read numProjects")? as usize;
    if num_projects > 4096 {
        return Err("too many module descriptors in _VBA_PROJECT stream".into());
    }
    offset += 2;
    for _ in 0..num_projects {
        let w_len = read_u16(data, offset).ok_or("cannot read module wLength")? as usize;
        offset += 2;
        if unicode_name {
            offset += w_len;
        }
        if non_unicode_name && w_len > 0 {
            let w_len2 = read_u16(data, offset).unwrap_or(0) as usize;
            offset += 2 + w_len2;
        }
        offset =
            skip_structure(data, offset, false, 1, false).ok_or("failed skipping stream time")?;
        offset =
            skip_structure(data, offset, false, 1, true).ok_or("failed skipping module doc")?;
        offset += 2;
        if version >= 0x6B {
            offset = skip_structure(data, offset, false, 1, true)
                .ok_or("failed skipping module help")?;
        }
        offset =
            skip_structure(data, offset, false, 1, true).ok_or("failed skipping module extra")?;
        offset += 2;
        if version != 0x51 {
            offset += 4;
        }
        offset =
            skip_structure(data, offset, false, 8, false).ok_or("failed skipping module tail")?;
        offset += 11;
    }

    offset += 6;
    offset =
        skip_structure(data, offset, true, 1, false).ok_or("failed skipping table before IDs")?;
    offset += 6;

    if offset + 6 > data.len() {
        return Err("truncated before identifier table counts".into());
    }
    let w0 = read_u16(data, offset).ok_or("cannot read w0")? as i32;
    let num_total_ids = read_u16(data, offset + 2).ok_or("cannot read numIDs")? as i32;
    let w1 = read_u16(data, offset + 4).ok_or("cannot read w1")? as i32;
    offset += 10;

    let num_junk_ids = num_total_ids + w1 - w0;
    let num_ids = w0 - w1;

    if num_junk_ids < 0 || num_ids < 0 {
        return Err("inconsistent identifier table counts".into());
    }

    // Skip junk IDs
    for _ in 0..num_junk_ids {
        if offset + 6 > data.len() {
            return Err("truncated in junk IDs".into());
        }
        offset += 4;
        let id_type = data[offset];
        let id_length = data[offset + 1] as usize;
        offset += 2;
        if id_type > 0x7F {
            offset += 6;
        }
        offset += id_length;
    }

    // Parse real variable names
    let mut identifiers = Vec::with_capacity((num_ids as usize).min(4096));
    for _ in 0..num_ids {
        if offset + 2 > data.len() {
            break;
        }
        let mut is_kwd = false;
        let mut id_type = data[offset];
        let mut id_length = data[offset + 1] as usize;
        offset += 2;

        if id_length == 0 && id_type == 0 {
            if offset + 2 > data.len() {
                break;
            }
            offset += 2;
            id_type = data[offset];
            id_length = data[offset + 1] as usize;
            offset += 2;
            is_kwd = true;
        }

        if id_type & 0x80 != 0 {
            offset += 6;
        }

        if id_length > 0 && offset + id_length <= data.len() {
            let bytes = &data[offset..offset + id_length];
            let ident_str = String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| bytes.iter().map(|&b| b as char).collect());
            identifiers.push(ident_str);
            offset += id_length;
        } else {
            identifiers.push(String::new());
        }

        if !is_kwd {
            offset += 4;
        }
    }

    Ok(identifiers)
}

/// Decoded operand value with accurate typed representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PCodeOperandValue {
    Integer(i64),
    Float(String),
    Date(String),
    Currency(String),
    SpecialVariant(&'static str),
    StringLit(String),
    NameRef(String),
    RawWord(u16),
    RawDword(u32),
    TargetAddress(usize),
}

/// Disassembled instruction detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassembledInstruction {
    pub offset: usize,
    pub opcode: u16,
    pub op_type: u16,
    pub mnemonic: String,
    pub formatted: String,
    pub target_name: Option<String>,
    pub string_literal: Option<String>,
    pub is_call: bool,
    pub is_branch: bool,
    pub jump_target: Option<usize>,
    pub detailed_operands: Vec<PCodeOperandValue>,
}

impl DisassembledInstruction {
    /// Create a simple instruction with default operand collections.
    pub fn simple(
        offset: usize,
        opcode: u16,
        op_type: u16,
        mnemonic: impl Into<String>,
        formatted: impl Into<String>,
    ) -> Self {
        Self {
            offset,
            opcode,
            op_type,
            mnemonic: mnemonic.into(),
            formatted: formatted.into(),
            target_name: None,
            string_literal: None,
            is_call: false,
            is_branch: false,
            jump_target: None,
            detailed_operands: Vec::new(),
        }
    }
}

/// Disassembled P-code source line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassembledPCodeLine {
    pub line_number: usize,
    pub instructions: Vec<DisassembledInstruction>,
    pub formatted_text: String,
}

/// Disassembled module containing all instructions, extracted procedures, calls, and strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassembledPCodeModule {
    pub module_name: String,
    pub lines: Vec<DisassembledPCodeLine>,
    pub declared_procedures: Vec<String>,
    pub string_literals: Vec<String>,
    pub called_procedures: Vec<String>,
    pub is_stomped_suspect: bool,
}

/// Decode an OLE Automation Date serial into an ISO-like date-time string if valid.
fn decode_ole_date(serial: f64) -> String {
    if !serial.is_finite() || !(0.0..=2958465.0).contains(&serial) {
        return format!("#{:.4}#", serial);
    }
    let total_days = serial.floor() as i64;
    let frac = (serial - serial.floor()).abs();
    let total_seconds = (frac * 86400.0 + 0.5) as u32;
    let sec = total_seconds % 60;
    let min = (total_seconds / 60) % 60;
    let hour = (total_seconds / 3600) % 24;

    // VBA base date 1899-12-30
    let mut year = 1899i32;
    let mut month = 12u32;
    let mut day = 30u32;

    let days_in_month = |y: i32, m: u32| -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
                    29
                } else {
                    28
                }
            }
            _ => 30,
        }
    };

    let mut remaining = total_days;
    while remaining > 0 {
        let dim = days_in_month(year, month);
        let left_in_month = dim - day;
        if remaining as u32 <= left_in_month {
            day += remaining as u32;
            remaining = 0;
        } else {
            remaining -= (left_in_month + 1) as i64;
            day = 1;
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }
        }
    }

    if total_seconds > 0 {
        format!("#{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}#")
    } else {
        format!("#{year:04}-{month:02}-{day:02}#")
    }
}

/// Disassemble module P-code bytes into a human-readable, structured report.
pub fn disassemble_pcode_module(
    module_name: &str,
    module_stream: &[u8],
    _declared_text_offset: u32,
    identifiers: &[String],
    is_64bit: bool,
    vba_ver: u16,
) -> Result<DisassembledPCodeModule, String> {
    let line_map_opt = inspect_vba7_line_map(
        module_stream,
        crate::compiled::PCodeLayoutProfile::Vba7Observed,
        65_535,
    )?;
    let line_map = match line_map_opt {
        Some(m) => m,
        None => {
            return Ok(DisassembledPCodeModule {
                module_name: module_name.to_string(),
                lines: Vec::new(),
                declared_procedures: Vec::new(),
                string_literals: Vec::new(),
                called_procedures: Vec::new(),
                is_stomped_suspect: false,
            });
        }
    };
    let mut disasm_lines = Vec::with_capacity(line_map.lines.len());
    let mut declared_procedures = Vec::new();
    let mut string_literals = Vec::new();
    let mut called_procedures = Vec::new();

    for line in &line_map.lines {
        let mut offset = 0;
        let bytes = &line.raw_bytes;
        let mut line_instructions = Vec::new();
        let mut formatted_line = format!("Line #{}:\n", line.source_line);

        while offset + 2 <= bytes.len() {
            let inst_start_offset = offset;
            let header = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;
            let raw_opcode = header & 0x03FF;
            let op_type = (header & 0xFC00) >> 10;
            let translated = translate_opcode(raw_opcode, vba_ver, is_64bit);

            let meta = STANDARD_VBA7_OPCODES
                .iter()
                .find(|m| m.opcode == translated);

            let mnemonic = meta
                .map(|m| m.mnemonic.to_string())
                .unwrap_or_else(|| format!("Op_0x{:04X}", raw_opcode));

            let mut formatted_inst = format!("\t{:04X} {} ", raw_opcode, mnemonic);
            let mut target_name = None;
            let mut string_literal = None;
            let mut is_call = false;
            let mut is_branch = false;
            let mut jump_target = None;
            let mut detailed_operands = Vec::new();

            if matches!(
                mnemonic.as_str(),
                "ArgsCall" | "ArgsMemCall" | "ArgsMemCallWith" | "GoSub"
            ) {
                is_call = true;
            }
            if matches!(
                mnemonic.as_str(),
                "GoTo" | "OnGoto" | "OnGosub" | "If" | "IfBlock" | "ElseIfBlock"
            ) {
                is_branch = true;
            }

            // Special opcode handlers
            if mnemonic == "LitSmallI2" {
                let val = op_type as i64;
                formatted_inst.push_str(&format!("{val} "));
                detailed_operands.push(PCodeOperandValue::Integer(val));
            } else if mnemonic == "LitVarSpecial" {
                let special = match op_type {
                    0 => "Empty",
                    1 => "Null",
                    2 => "0",
                    3 => "1",
                    4 => "True",
                    5 => "False",
                    6 => "Missing",
                    7 => "Nothing",
                    _ => "SpecialVariant",
                };
                formatted_inst.push_str(&format!("{special} "));
                detailed_operands.push(PCodeOperandValue::SpecialVariant(special));
            }

            if let Some(m) = meta {
                for &arg in m.args {
                    match arg {
                        PCodeArgKind::Name => {
                            if offset + 2 <= bytes.len() {
                                let id_word =
                                    u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
                                offset += 2;
                                let name = if mnemonic == "OnError" && id_word == 0 {
                                    "0 (Resume 0)".to_string()
                                } else if mnemonic == "OnError" && id_word == 1 {
                                    "Resume Next".to_string()
                                } else {
                                    get_id(id_word, identifiers, vba_ver, is_64bit)
                                };
                                formatted_inst.push_str(&format!("{} ", name));
                                detailed_operands.push(PCodeOperandValue::NameRef(name.clone()));
                                if target_name.is_none() {
                                    target_name = Some(name.clone());
                                }
                                if is_call && !called_procedures.contains(&name) {
                                    called_procedures.push(name.clone());
                                }
                                if mnemonic == "FuncDefn" && !declared_procedures.contains(&name) {
                                    declared_procedures.push(name);
                                }
                            }
                        }
                        PCodeArgKind::HexWord | PCodeArgKind::Imp => {
                            if offset + 2 <= bytes.len() {
                                let val = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
                                offset += 2;
                                match mnemonic.as_str() {
                                    "LitDI2" => {
                                        let sval = val as i16 as i64;
                                        formatted_inst.push_str(&format!("{sval} "));
                                        detailed_operands.push(PCodeOperandValue::Integer(sval));
                                    }
                                    "LitHI2" => {
                                        formatted_inst.push_str(&format!("&H{:04X} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawWord(val));
                                    }
                                    "LitOI2" => {
                                        formatted_inst.push_str(&format!("&O{:o} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawWord(val));
                                    }
                                    "Branch" | "BranchF" | "BranchT" | "GoSub" | "GoTo" => {
                                        let rel = val as i16 as isize;
                                        let target = (offset as isize + rel).max(0) as usize;
                                        jump_target = Some(target);
                                        formatted_inst.push_str(&format!("loc_{:04X} ", target));
                                        detailed_operands
                                            .push(PCodeOperandValue::TargetAddress(target));
                                    }
                                    _ => {
                                        formatted_inst.push_str(&format!("0x{:04X} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawWord(val));
                                    }
                                }
                            }
                        }
                        PCodeArgKind::Func
                        | PCodeArgKind::Var
                        | PCodeArgKind::Rec
                        | PCodeArgKind::TypeDesc
                        | PCodeArgKind::Context => {
                            if offset + 4 <= bytes.len() {
                                let val = u32::from_le_bytes([
                                    bytes[offset],
                                    bytes[offset + 1],
                                    bytes[offset + 2],
                                    bytes[offset + 3],
                                ]);
                                offset += 4;
                                match mnemonic.as_str() {
                                    "LitDI4" => {
                                        let sval = val as i32 as i64;
                                        formatted_inst.push_str(&format!("{sval} "));
                                        detailed_operands.push(PCodeOperandValue::Integer(sval));
                                    }
                                    "LitHI4" => {
                                        formatted_inst.push_str(&format!("&H{:08X} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawDword(val));
                                    }
                                    "LitOI4" => {
                                        formatted_inst.push_str(&format!("&O{:o} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawDword(val));
                                    }
                                    "LitR4" => {
                                        let fval = f32::from_bits(val);
                                        formatted_inst.push_str(&format!("{fval}f32 "));
                                        detailed_operands
                                            .push(PCodeOperandValue::Float(format!("{fval}")));
                                    }
                                    _ => {
                                        formatted_inst.push_str(&format!("0x{:08X} ", val));
                                        detailed_operands.push(PCodeOperandValue::RawDword(val));
                                    }
                                }
                                if arg == PCodeArgKind::Func {
                                    let low = (val & 0xFFFF) as u16;
                                    let high = ((val >> 16) & 0xFFFF) as u16;
                                    let name_cand = get_id(low, identifiers, vba_ver, is_64bit);
                                    let resolved = if !name_cand.starts_with("id_") {
                                        Some(name_cand)
                                    } else {
                                        let high_cand =
                                            get_id(high, identifiers, vba_ver, is_64bit);
                                        if !high_cand.starts_with("id_") {
                                            Some(high_cand)
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(proc_name) = resolved {
                                        formatted_inst.push_str(&format!("({}) ", proc_name));
                                        if !declared_procedures.contains(&proc_name) {
                                            declared_procedures.push(proc_name.clone());
                                        }
                                        if target_name.is_none() {
                                            target_name = Some(proc_name);
                                        }
                                    }
                                }
                            }
                            if is_64bit && arg == PCodeArgKind::Context && offset + 4 <= bytes.len()
                            {
                                let val2 = u32::from_le_bytes([
                                    bytes[offset],
                                    bytes[offset + 1],
                                    bytes[offset + 2],
                                    bytes[offset + 3],
                                ]);
                                offset += 4;
                                formatted_inst.push_str(&format!("0x{:08X} ", val2));
                                detailed_operands.push(PCodeOperandValue::RawDword(val2));
                            }
                        }
                    }
                }

                // Quad-word literals (LitR8, LitCy, LitDate)
                if matches!(mnemonic.as_str(), "LitR8" | "LitCy" | "LitDate")
                    && detailed_operands.len() >= 4
                {
                    // Collect four words into 64-bit value
                    let mut q_bytes = [0u8; 8];
                    let mut q_valid = true;
                    for (i, op) in detailed_operands[detailed_operands.len() - 4..]
                        .iter()
                        .enumerate()
                    {
                        if let PCodeOperandValue::RawWord(w) = op {
                            q_bytes[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
                        } else {
                            q_valid = false;
                            break;
                        }
                    }
                    if q_valid {
                        detailed_operands.truncate(detailed_operands.len() - 4);
                        let qval = u64::from_le_bytes(q_bytes);
                        match mnemonic.as_str() {
                            "LitR8" => {
                                let fval = f64::from_bits(qval);
                                detailed_operands.push(PCodeOperandValue::Float(format!("{fval}")));
                                formatted_inst =
                                    format!("\t{:04X} {} {} ", raw_opcode, mnemonic, fval);
                            }
                            "LitDate" => {
                                let fval = f64::from_bits(qval);
                                let dstr = decode_ole_date(fval);
                                detailed_operands.push(PCodeOperandValue::Date(dstr.clone()));
                                formatted_inst =
                                    format!("\t{:04X} {} {} ", raw_opcode, mnemonic, dstr);
                            }
                            "LitCy" => {
                                let cy_raw = qval as i64;
                                let cy_scaled = (cy_raw as f64) / 10_000.0;
                                detailed_operands
                                    .push(PCodeOperandValue::Currency(format!("{cy_scaled:.4}@")));
                                formatted_inst =
                                    format!("\t{:04X} {} {:.4}@ ", raw_opcode, mnemonic, cy_scaled);
                            }
                            _ => {}
                        }
                    }
                }

                if m.varg && offset + 2 <= bytes.len() {
                    let w_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                    offset += 2;
                    if offset + w_len <= bytes.len() {
                        let payload = &bytes[offset..offset + w_len];
                        if matches!(mnemonic.as_str(), "LitStr" | "QuoteRem" | "Rem" | "Reparse") {
                            let text = String::from_utf8(payload.to_vec())
                                .unwrap_or_else(|_| payload.iter().map(|&b| b as char).collect());
                            formatted_inst.push_str(&format!("\"{}\" ", text));
                            if mnemonic == "LitStr" {
                                string_literal = Some(text.clone());
                                detailed_operands.push(PCodeOperandValue::StringLit(text.clone()));
                                if !string_literals.contains(&text) {
                                    string_literals.push(text);
                                }
                            }
                        } else {
                            formatted_inst.push_str(&format!("[payload {} bytes] ", w_len));
                        }
                        offset += w_len;
                        if w_len & 1 != 0 && offset < bytes.len() {
                            offset += 1;
                        }
                    } else {
                        // Truncated payload: consume remaining bytes of this line to avoid misinterpreting partial payload as instructions
                        formatted_inst.push_str(&format!(
                            "[truncated payload {}/{} bytes] ",
                            bytes.len().saturating_sub(offset),
                            w_len
                        ));
                        offset = bytes.len();
                    }
                }
            }

            formatted_line.push_str(&formatted_inst);
            formatted_line.push('\n');

            line_instructions.push(DisassembledInstruction {
                offset: inst_start_offset,
                opcode: raw_opcode,
                op_type,
                mnemonic,
                formatted: formatted_inst.trim().to_string(),
                target_name,
                string_literal,
                is_call,
                is_branch,
                jump_target,
                detailed_operands,
            });
        }

        disasm_lines.push(DisassembledPCodeLine {
            line_number: line.source_line,
            instructions: line_instructions,
            formatted_text: formatted_line,
        });
    }

    Ok(DisassembledPCodeModule {
        module_name: module_name.to_string(),
        lines: disasm_lines,
        declared_procedures,
        string_literals,
        called_procedures,
        is_stomped_suspect: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vba7_schema_validates() {
        let schema32 = standard_vba7_instruction_schema(false);
        assert!(schema32.validate().is_ok());
        assert_eq!(schema32.definitions.len(), 264);

        let schema64 = standard_vba7_instruction_schema(true);
        assert!(schema64.validate().is_ok());
        assert_eq!(schema64.definitions.len(), 264);
    }

    #[test]
    fn standard_vba6_schema_validates() {
        let schema = standard_vba6_instruction_schema();
        assert!(schema.validate().is_ok());
        assert_eq!(schema.definitions.len(), 264);
    }

    #[test]
    fn internal_names_resolution() {
        let idents: Vec<String> = vec!["MyCustomVar".into(), "DoSomething".into()];
        // id_code >>= 1 -> index
        // internalNames: 16 -> "Boolean", 20 -> "Call", 176 -> "Sub"
        assert_eq!(get_id(16 << 1, &idents, 7, false), "Boolean");
        assert_eq!(get_id(20 << 1, &idents, 7, false), "Call");
        assert_eq!(get_id(176 << 1, &idents, 7, false), "Sub");

        // User identifiers: offset 0x100
        // In VBA7 32-bit: idx = (id_code - 0x100) - 4
        // To get idx 0 ("MyCustomVar"): id_code = 0x104
        assert_eq!(get_id(0x104 << 1, &idents, 7, false), "MyCustomVar");
        assert_eq!(get_id(0x105 << 1, &idents, 7, false), "DoSomething");
    }

    #[test]
    fn translate_opcode_mappings() {
        assert_eq!(translate_opcode(10, 7, true), 10);
        assert_eq!(translate_opcode(10, 7, false), 10);
        assert_eq!(translate_opcode(180, 7, false), 183);
        assert_eq!(translate_opcode(100, 3, false), 104);
        assert_eq!(translate_opcode(100, 5, false), 103);
    }

    #[test]
    fn parses_synthetic_vba_project_identifiers() {
        let mut buf = Vec::new();
        // Magic 0x61CC
        buf.extend_from_slice(&0x61CCu16.to_le_bytes());
        // Version 0x0097 (VBA7)
        buf.extend_from_slice(&0x0097u16.to_le_bytes());
        // Endian word
        buf.extend_from_slice(&0x0000u16.to_le_bytes());
        buf.resize(0x1E, 0);
        // numRefs = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // skip 2
        // Class table length = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Compile pairs length = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // +2
        // TypeInfo length = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Project desc length = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Help file length = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // + 0x64
        buf.resize(buf.len() + 0x64, 0);
        // numProjects = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // + 6
        buf.extend_from_slice(&[0; 6]);
        // Table before IDs dword length = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // + 6
        buf.extend_from_slice(&[0; 6]);
        // w0 = 2, numIDs = 0, w1 = 0 -> num_ids = 2 - 0 = 2, junk = 0 + 0 - 2 = -2 (must be non-negative)
        // Let w0 = 2, numIDs = 2, w1 = 0 -> num_junk = 2 + 0 - 2 = 0, num_ids = 2 - 0 = 2.
        buf.extend_from_slice(&2u16.to_le_bytes()); // w0
        buf.extend_from_slice(&2u16.to_le_bytes()); // num_total_ids
        buf.extend_from_slice(&0u16.to_le_bytes()); // w1
        buf.extend_from_slice(&[0; 4]); // +4

        // Identifier 1: type=0, length=4, "test", +4 bytes
        buf.push(0); // id_type
        buf.push(4); // id_len
        buf.extend_from_slice(b"test");
        buf.extend_from_slice(&[0; 4]);

        // Identifier 2: type=0, length=5, "hello", +4 bytes
        buf.push(0); // id_type
        buf.push(5); // id_len
        buf.extend_from_slice(b"hello");
        buf.extend_from_slice(&[0; 4]);

        let idents = parse_vba_project_identifiers(&buf).unwrap();
        assert_eq!(idents, vec!["test".to_string(), "hello".to_string()]);
    }

    #[test]
    fn decodes_ole_automation_date() {
        // Serial 0.0 -> 1899-12-30
        assert_eq!(decode_ole_date(0.0), "#1899-12-30#");
        // Serial 2.0 -> 1900-01-01
        assert_eq!(decode_ole_date(2.0), "#1900-01-01#");
        // Serial with time (fraction 0.5 = 12:00:00)
        assert_eq!(decode_ole_date(2.5), "#1900-01-01 12:00:00#");
    }

    #[test]
    fn pcode_operand_values_instantiation() {
        let op_int = PCodeOperandValue::Integer(12345);
        let op_flt = PCodeOperandValue::Float("3.1415".into());
        let op_special = PCodeOperandValue::SpecialVariant("True");
        let op_target = PCodeOperandValue::TargetAddress(0x120);

        assert_eq!(op_int, PCodeOperandValue::Integer(12345));
        assert_ne!(op_int, op_flt);
        assert_eq!(op_special, PCodeOperandValue::SpecialVariant("True"));
        assert_eq!(op_target, PCodeOperandValue::TargetAddress(0x120));
    }
}
