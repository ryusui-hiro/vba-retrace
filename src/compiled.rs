//! Structural inspection of VBA compiled-cache regions.
//!
//! MS-OVBA defines module/project performance caches as implementation and
//! version dependent. This module validates their boundaries and fingerprints
//! the bytes. Optional decoding and abstract evaluation accept caller-supplied
//! schemas, but never claim portable or build-verified p-code semantics.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCacheInspection {
    pub reserved1: u16,
    pub version: u16,
    pub reserved2: u8,
    pub reserved3: u16,
    pub cache_length: usize,
    pub fingerprint_fnv1a64: u64,
    pub header_well_formed: bool,
    pub pcode_disassembled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleCacheInspection {
    pub declared_text_offset: u32,
    pub cache_length: usize,
    pub fingerprint_fnv1a64: u64,
    pub source_container_signature_valid: bool,
    pub pcode_disassembled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeLayoutProfile {
    /// Observed line-map layout used by modern VBA7 module caches.
    /// This profile identifies framing only; it does not identify a specific Office build.
    Vba7Observed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeLineSegment {
    pub source_line: usize,
    pub line_length: u16,
    /// Uninterpreted first four bytes of this observed line record.
    pub record_prefix_raw: [u8; 4],
    /// Uninterpreted bytes following the line length in this observed record.
    pub record_middle_raw: [u8; 2],
    /// Raw relative code offset; `u32::MAX` is retained as observed.
    pub relative_code_offset_raw: u32,
    pub cache_offset: Option<usize>,
    pub raw_bytes: Vec<u8>,
    pub raw_word_count: usize,
    pub has_partial_word: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeLineMap {
    pub profile: PCodeLayoutProfile,
    pub cafe_offset: usize,
    /// Two bytes between the observed CAFE marker and line count; meaning unknown.
    pub profile_header_raw: [u8; 2],
    pub line_count: usize,
    pub directory_offset: usize,
    pub code_table_offset: usize,
    pub code_bytes_total: usize,
    pub lines: Vec<PCodeLineSegment>,
    pub mnemonics_decoded: bool,
}

impl PCodeLineMap {
    /// Validate a caller-provided line map before decoding. This checks only
    /// internal lengths, word counts, and monotonic cache offsets; it does not
    /// identify a VBA build or prove that the map came from Office.
    pub fn validate(&self) -> Result<(), String> {
        if self.line_count != self.lines.len() {
            return Err("p-code line map count does not match its line records".into());
        }
        let mut total = 0usize;
        let mut previous_end = None;
        for line in &self.lines {
            let missing_code =
                line.relative_code_offset_raw == u32::MAX && line.cache_offset.is_none();
            if missing_code {
                if !line.raw_bytes.is_empty() || line.raw_word_count != 0 || line.has_partial_word {
                    return Err(format!(
                        "p-code line {} marks missing code but retains raw bytes",
                        line.source_line
                    ));
                }
                continue;
            }
            if line.line_length as usize != line.raw_bytes.len() {
                return Err(format!(
                    "p-code line {} length does not match its raw bytes",
                    line.source_line
                ));
            }
            if line.raw_word_count != line.raw_bytes.len() / 2
                || line.has_partial_word != (line.raw_bytes.len() & 1 != 0)
            {
                return Err(format!(
                    "p-code line {} word-count metadata is inconsistent",
                    line.source_line
                ));
            }
            total = total
                .checked_add(line.raw_bytes.len())
                .ok_or("p-code line byte count overflow")?;
            if let Some(offset) = line.cache_offset {
                let end = offset
                    .checked_add(line.raw_bytes.len())
                    .ok_or("p-code line cache offset overflow")?;
                if previous_end.is_some_and(|previous| offset < previous) {
                    return Err("p-code line cache offsets are not monotonic".into());
                }
                previous_end = Some(end);
            }
        }
        if total != self.code_bytes_total {
            return Err("p-code line byte total does not match the line records".into());
        }
        Ok(())
    }
}

/// Caller-supplied description of the operands following one raw 16-bit word.
/// The decoder reads each fixed-width value little-endian. A byte payload is
/// prefixed by a little-endian `u16` byte count; when requested, one padding
/// byte follows odd-length payloads. This carries no built-in VBA assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PCodeOperandEncoding {
    Byte8,
    Word16,
    SignedWord16,
    DoubleWord32,
    SignedDoubleWord32,
    QuadWord64,
    /// Preserve an IEEE-754 binary64 operand as its raw little-endian bits.
    Float64Bits,
    BytesPrefixedByWord {
        pad_odd_payload_to_even: bool,
    },
}

/// Caller-supplied opcode description for a specific observed p-code schema.
/// `opcode` is the value after the schema's opcode mask is shifted right.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeOpcodeDefinition {
    pub opcode: u16,
    /// Optional operation type extracted from the same instruction header.
    /// An exact operation-type definition takes precedence over a generic
    /// `None` definition for the same opcode.
    pub operation_type: Option<u16>,
    pub mnemonic: String,
    pub operands: Vec<PCodeOperandEncoding>,
}

/// An explicit, non-standard schema for decoding 16-bit p-code line words.
/// Callers must provide version-specific opcode and operand knowledge.
///
/// The masks must describe non-overlapping contiguous bit fields, and each
/// shift must equal that field's least-significant bit position. An operation
/// type mask of zero disables operation-type extraction. Opcode definition
/// values use the shifted, unmasked opcode value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeInstructionSchema {
    pub id: String,
    pub opcode_mask: u16,
    pub opcode_shift: u8,
    pub operation_type_mask: u16,
    pub operation_type_shift: u8,
    pub definitions: Vec<PCodeOpcodeDefinition>,
}

impl PCodeInstructionSchema {
    /// Validate caller-supplied opcode/operand metadata without decoding a
    /// line map. This checks schema shape only and never verifies an Office
    /// build or assigns meanings to the opcodes.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 128 {
            return Err("p-code schema id must contain 1 to 128 bytes".into());
        }
        if !valid_shifted_bit_field(self.opcode_mask, self.opcode_shift) {
            return Err("p-code schema has an invalid opcode bit field".into());
        }
        if self.operation_type_mask != 0
            && !valid_shifted_bit_field(self.operation_type_mask, self.operation_type_shift)
        {
            return Err("p-code schema has an invalid operation-type bit field".into());
        }
        if self.opcode_mask & self.operation_type_mask != 0 {
            return Err("p-code opcode and operation-type bit fields overlap".into());
        }
        if self.definitions.is_empty() || self.definitions.len() > 4096 {
            return Err("p-code schema must contain 1 to 4096 opcode definitions".into());
        }
        let opcode_values = self.opcode_mask >> self.opcode_shift;
        let operation_type_values = if self.operation_type_mask == 0 {
            0
        } else {
            self.operation_type_mask >> self.operation_type_shift
        };
        let mut definitions = HashSet::new();
        for definition in &self.definitions {
            if definition.mnemonic.is_empty() || definition.mnemonic.len() > 128 {
                return Err("p-code mnemonic must contain 1 to 128 bytes".into());
            }
            if definition.opcode & !opcode_values != 0 {
                return Err(format!(
                    "opcode 0x{:04x} does not fit the configured bit field",
                    definition.opcode
                ));
            }
            if let Some(operation_type) = definition.operation_type {
                if self.operation_type_mask == 0 {
                    return Err(format!(
                        "opcode 0x{:04x} constrains an operation type but the schema has no operation-type field",
                        definition.opcode
                    ));
                }
                if operation_type & !operation_type_values != 0 {
                    return Err(format!(
                        "operation type 0x{operation_type:04x} for opcode 0x{:04x} does not fit the configured bit field",
                        definition.opcode
                    ));
                }
            }
            if definition.operands.len() > 64 {
                return Err(format!(
                    "opcode 0x{:04x} exceeds the 64-operand schema limit",
                    definition.opcode
                ));
            }
            if !definitions.insert((definition.opcode, definition.operation_type)) {
                return Err(format!(
                    "duplicate p-code definition for opcode 0x{:04x} and operation type {:?}",
                    definition.opcode, definition.operation_type
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedPCodeOperand {
    Byte8(u8),
    Word16(u16),
    SignedWord16(i16),
    DoubleWord32(u32),
    SignedDoubleWord32(i32),
    QuadWord64(u64),
    Float64Bits(u64),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedPCodeInstruction {
    pub source_line: usize,
    pub line_offset: usize,
    pub cache_offset: Option<usize>,
    pub header_word: u16,
    pub opcode: u16,
    pub operation_type: u16,
    pub mnemonic: Option<String>,
    pub operands: Vec<DecodedPCodeOperand>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeDecodeIssueKind {
    UnknownOpcode,
    UnknownOperationType,
    TruncatedHeader,
    TruncatedOperand,
    TruncatedPayloadPadding,
    InstructionLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeDecodeIssue {
    pub source_line: usize,
    pub line_offset: usize,
    pub cache_offset: Option<usize>,
    pub kind: PCodeDecodeIssueKind,
    pub raw_header_word: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeSchemaStatus {
    CallerSuppliedUnverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedPCodeLine {
    pub source_line: usize,
    pub instructions: Vec<DecodedPCodeInstruction>,
    pub issues: Vec<PCodeDecodeIssue>,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeDecodeReport {
    pub schema_id: String,
    pub schema_status: PCodeSchemaStatus,
    pub lines: Vec<DecodedPCodeLine>,
    pub instruction_count: usize,
    /// Whether every word was decoded under the supplied schema. This is not
    /// proof that the schema matches an Office build or the module source.
    pub complete: bool,
    pub truncated: bool,
}

/// Abstract values produced while applying a caller-supplied p-code semantic
/// specification. Values that depend on runtime state remain `Unknown`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PCodeSemanticValue {
    Unknown,
    Null,
    Empty,
    Error(i32),
    Integer(i64),
    Boolean(bool),
    String(String),
    Float64Bits(u64),
    Bytes(Vec<u8>),
    /// Caller-assigned object identity. The numeric key has no Office-wide
    /// meaning; it is only useful for equality/alias evidence inside a schema.
    Object(u64),
    /// Bounded array payload supplied explicitly by the caller. Runtime
    /// arrays remain `Unknown` unless the schema chooses to model them.
    Array(Vec<PCodeSemanticValue>),
}

/// Encoding selected by a caller when a raw byte operand is known to carry a
/// string. The decoder never assumes either encoding from an opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeStringEncoding {
    Utf8,
    Utf16Le,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeBinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    LessThan,
    LessOrEqual,
    GreaterThan,
    GreaterOrEqual,
    And,
    Or,
    Xor,
    Eqv,
    Imp,
    Concat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeUnaryOperator {
    Negate,
    Not,
    IsObject,
    IsArray,
    ArrayLength,
}

/// Stack action for one caller-supplied opcode definition. This is intentionally
/// separate from the byte decoder: a schema can describe observed operand
/// widths while a second, version-specific specification describes meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PCodeSemanticAction {
    PushOperand {
        operand_index: usize,
    },
    /// Convert a caller-supplied integer operand into a VBA-style Error value.
    PushErrorOperand {
        operand_index: usize,
    },
    PushStringOperand {
        operand_index: usize,
        encoding: PCodeStringEncoding,
    },
    /// Preserve an operand as a caller-defined object identity.
    PushObjectOperand {
        operand_index: usize,
    },
    PushLiteral(PCodeSemanticValue),
    LoadSlot {
        slot: u64,
    },
    StoreSlot {
        slot: u64,
    },
    Unary(PCodeUnaryOperator),
    Binary(PCodeBinaryOperator),
    Drop,
    Duplicate,
    /// Read one element from an explicitly modeled bounded array. The array
    /// and zero-based integer index are popped from the abstract stack.
    ArrayIndex,
    /// Record a relative branch operand without pretending to resolve the
    /// target against source lines or a version-specific instruction table.
    BranchRelative {
        operand_index: usize,
    },
    /// Pop a Boolean/integer condition and record a caller-defined conditional
    /// relative branch. Unknown conditions retain both paths during bounded
    /// exploration; known conditions select one path.
    BranchRelativeIf {
        operand_index: usize,
    },
    /// Consume arguments and record a call candidate. The target encoding is
    /// preserved as an abstract operand value.
    Call {
        target_operand_index: Option<usize>,
        argument_count: usize,
        returns_value: bool,
    },
    /// Caller-supplied summary for a call whose return value is known from
    /// the selected semantic schema (for example a modeled intrinsic).
    CallKnownReturn {
        target_operand_index: Option<usize>,
        argument_count: usize,
        return_value: PCodeSemanticValue,
    },
    Return {
        has_value: bool,
    },
    InvalidateStack,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticDefinition {
    pub opcode: u16,
    pub operation_type: Option<u16>,
    pub actions: Vec<PCodeSemanticAction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticSchema {
    pub id: String,
    pub definitions: Vec<PCodeSemanticDefinition>,
    pub max_stack: usize,
}

impl PCodeSemanticSchema {
    /// Validate a caller-supplied semantic action table without requiring a
    /// decoded line map. This checks only schema shape and resource bounds;
    /// compatibility with an Office build remains the caller's responsibility.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > 128 {
            return Err("p-code semantic schema id must contain 1 to 128 bytes".into());
        }
        if self.max_stack == 0 || self.max_stack > 4096 {
            return Err("p-code semantic schema max_stack must be between 1 and 4096".into());
        }
        if self.definitions.is_empty() || self.definitions.len() > 4096 {
            return Err("p-code semantic schema must contain 1 to 4096 definitions".into());
        }
        let mut keys = HashSet::new();
        for definition in &self.definitions {
            if definition.actions.len() > 128 {
                return Err(format!(
                    "opcode 0x{:04x} exceeds the 128-action semantic limit",
                    definition.opcode
                ));
            }
            if !keys.insert((definition.opcode, definition.operation_type)) {
                return Err(format!(
                    "duplicate p-code semantic definition for opcode 0x{:04x} and operation type {:?}",
                    definition.opcode, definition.operation_type
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PCodeSemanticControlTransfer {
    None,
    BranchRelative(PCodeSemanticValue),
    ConditionalBranchRelative {
        target: PCodeSemanticValue,
        condition: PCodeSemanticValue,
    },
    Call {
        target: Option<PCodeSemanticValue>,
        returns_value: bool,
    },
    Return(Option<PCodeSemanticValue>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeSemanticStepStatus {
    Applied,
    UnknownInstruction,
    UnknownValue,
    StackUnderflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticStep {
    pub source_line: usize,
    pub line_offset: usize,
    pub opcode: u16,
    pub operation_type: u16,
    pub mnemonic: Option<String>,
    pub stack_before: Vec<PCodeSemanticValue>,
    pub stack_after: Vec<PCodeSemanticValue>,
    pub locals_before: Vec<(u64, PCodeSemanticValue)>,
    pub locals_after: Vec<(u64, PCodeSemanticValue)>,
    pub control_transfer: PCodeSemanticControlTransfer,
    pub status: PCodeSemanticStepStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticReport {
    pub schema_id: String,
    pub schema_status: PCodeSchemaStatus,
    pub steps: Vec<PCodeSemanticStep>,
    pub unknown_value_count: usize,
    pub unknown_instruction_count: usize,
    pub stack_underflow_count: usize,
    pub complete: bool,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeBranchBase {
    /// The relative target is measured from the current instruction address.
    InstructionStart,
    /// The relative target is measured from the next decoded instruction in
    /// the same source line, falling back to the next two-byte word.
    NextInstruction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PCodeSemanticPathTermination {
    EndOfStream,
    Return,
    UnknownInstruction,
    LoopBound,
    StepLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticPath {
    pub path_index: usize,
    pub steps: Vec<PCodeSemanticStep>,
    pub complete: bool,
    pub truncated: bool,
    pub termination: PCodeSemanticPathTermination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PCodeSemanticPathReport {
    pub schema_id: String,
    pub schema_status: PCodeSchemaStatus,
    pub paths: Vec<PCodeSemanticPath>,
    pub unknown_value_count: usize,
    pub unknown_instruction_count: usize,
    pub stack_underflow_count: usize,
    pub complete: bool,
    pub truncated: bool,
}

/// Decode observed per-source-line p-code using a caller-supplied schema.
///
/// The schema is experimental and is not checked against an Office build.
/// No opcode or operand table is bundled with this crate.
pub fn decode_pcode_lines_with_schema(
    line_map: &PCodeLineMap,
    schema: &PCodeInstructionSchema,
    max_instructions: usize,
) -> Result<PCodeDecodeReport, String> {
    line_map.validate()?;
    schema.validate()?;
    if schema.id.is_empty() || schema.id.len() > 128 {
        return Err("p-code schema id must contain 1 to 128 bytes".into());
    }
    if !valid_shifted_bit_field(schema.opcode_mask, schema.opcode_shift) {
        return Err("p-code schema has an invalid opcode bit field".into());
    }
    if schema.operation_type_mask != 0
        && !valid_shifted_bit_field(schema.operation_type_mask, schema.operation_type_shift)
    {
        return Err("p-code schema has an invalid operation-type bit field".into());
    }
    if schema.opcode_mask & schema.operation_type_mask != 0 {
        return Err("p-code opcode and operation-type bit fields overlap".into());
    }
    if schema.definitions.is_empty() || schema.definitions.len() > 4096 {
        return Err("p-code schema must contain 1 to 4096 opcode definitions".into());
    }
    if max_instructions == 0 {
        return Err("p-code instruction limit must be greater than zero".into());
    }
    let opcode_values = schema.opcode_mask >> schema.opcode_shift;
    let operation_type_values = if schema.operation_type_mask == 0 {
        0
    } else {
        schema.operation_type_mask >> schema.operation_type_shift
    };
    let mut definitions = HashMap::new();
    let mut known_opcodes = HashSet::new();
    for definition in &schema.definitions {
        if definition.mnemonic.is_empty() || definition.mnemonic.len() > 128 {
            return Err("p-code mnemonic must contain 1 to 128 bytes".into());
        }
        if definition.opcode & !opcode_values != 0 {
            return Err(format!(
                "opcode 0x{:04x} does not fit the configured bit field",
                definition.opcode
            ));
        }
        if let Some(operation_type) = definition.operation_type {
            if schema.operation_type_mask == 0 {
                return Err(format!(
                    "opcode 0x{:04x} constrains an operation type but the schema has no operation-type field",
                    definition.opcode
                ));
            }
            if operation_type & !operation_type_values != 0 {
                return Err(format!(
                    "operation type 0x{operation_type:04x} for opcode 0x{:04x} does not fit the configured bit field",
                    definition.opcode
                ));
            }
        }
        if definition.operands.len() > 64 {
            return Err(format!(
                "opcode 0x{:04x} exceeds the 64-operand schema limit",
                definition.opcode
            ));
        }
        let key = (definition.opcode, definition.operation_type);
        known_opcodes.insert(definition.opcode);
        if definitions.insert(key, definition).is_some() {
            return Err(format!(
                "duplicate p-code definition for opcode 0x{:04x} and operation type {:?}",
                definition.opcode, definition.operation_type
            ));
        }
    }

    let mut report = PCodeDecodeReport {
        schema_id: schema.id.clone(),
        schema_status: PCodeSchemaStatus::CallerSuppliedUnverified,
        lines: Vec::with_capacity(line_map.lines.len()),
        instruction_count: 0,
        complete: true,
        truncated: false,
    };
    for line in &line_map.lines {
        let mut decoded_line = DecodedPCodeLine {
            source_line: line.source_line,
            instructions: Vec::new(),
            issues: Vec::new(),
            complete: true,
        };
        let mut cursor = 0usize;
        while cursor < line.raw_bytes.len() {
            if report.instruction_count >= max_instructions {
                decoded_line.complete = false;
                decoded_line.issues.push(PCodeDecodeIssue {
                    source_line: line.source_line,
                    line_offset: cursor,
                    cache_offset: line
                        .cache_offset
                        .and_then(|offset| offset.checked_add(cursor)),
                    kind: PCodeDecodeIssueKind::InstructionLimit,
                    raw_header_word: None,
                });
                report.complete = false;
                report.truncated = true;
                report.lines.push(decoded_line);
                return Ok(report);
            }
            let instruction_start = cursor;
            let Some(header_end) = cursor.checked_add(2) else {
                return Err("p-code header offset overflow".into());
            };
            let Some(header_bytes) = line.raw_bytes.get(cursor..header_end) else {
                decoded_line.complete = false;
                decoded_line.issues.push(PCodeDecodeIssue {
                    source_line: line.source_line,
                    line_offset: cursor,
                    cache_offset: line
                        .cache_offset
                        .and_then(|offset| offset.checked_add(cursor)),
                    kind: PCodeDecodeIssueKind::TruncatedHeader,
                    raw_header_word: None,
                });
                report.complete = false;
                report.truncated = true;
                break;
            };
            let header_word = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
            cursor = header_end;
            let opcode = (header_word & schema.opcode_mask) >> schema.opcode_shift;
            let operation_type = if schema.operation_type_mask == 0 {
                0
            } else {
                (header_word & schema.operation_type_mask) >> schema.operation_type_shift
            };
            let definition = definitions
                .get(&(opcode, Some(operation_type)))
                .or_else(|| definitions.get(&(opcode, None)))
                .copied();
            let Some(definition) = definition else {
                let issue_kind = if known_opcodes.contains(&opcode) {
                    PCodeDecodeIssueKind::UnknownOperationType
                } else {
                    PCodeDecodeIssueKind::UnknownOpcode
                };
                decoded_line.instructions.push(DecodedPCodeInstruction {
                    source_line: line.source_line,
                    line_offset: instruction_start,
                    cache_offset: line
                        .cache_offset
                        .and_then(|offset| offset.checked_add(instruction_start)),
                    header_word,
                    opcode,
                    operation_type,
                    mnemonic: None,
                    operands: Vec::new(),
                    complete: false,
                });
                decoded_line.complete = false;
                decoded_line.issues.push(PCodeDecodeIssue {
                    source_line: line.source_line,
                    line_offset: instruction_start,
                    cache_offset: line
                        .cache_offset
                        .and_then(|offset| offset.checked_add(instruction_start)),
                    kind: issue_kind,
                    raw_header_word: Some(header_word),
                });
                report.complete = false;
                report.instruction_count += 1;
                break;
            };

            let mut operands = Vec::with_capacity(definition.operands.len());
            let mut issue = None;
            for encoding in &definition.operands {
                match encoding {
                    PCodeOperandEncoding::Byte8 => {
                        let Some(end) = cursor.checked_add(1) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::Byte8(bytes[0]));
                        cursor = end;
                    }
                    PCodeOperandEncoding::Word16 => {
                        let Some(end) = cursor.checked_add(2) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::Word16(u16::from_le_bytes([
                            bytes[0], bytes[1],
                        ])));
                        cursor = end;
                    }
                    PCodeOperandEncoding::SignedWord16 => {
                        let Some(end) = cursor.checked_add(2) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::SignedWord16(i16::from_le_bytes([
                            bytes[0], bytes[1],
                        ])));
                        cursor = end;
                    }
                    PCodeOperandEncoding::DoubleWord32 => {
                        let Some(end) = cursor.checked_add(4) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::DoubleWord32(u32::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        ])));
                        cursor = end;
                    }
                    PCodeOperandEncoding::SignedDoubleWord32 => {
                        let Some(end) = cursor.checked_add(4) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::SignedDoubleWord32(i32::from_le_bytes(
                            [bytes[0], bytes[1], bytes[2], bytes[3]],
                        )));
                        cursor = end;
                    }
                    PCodeOperandEncoding::QuadWord64 | PCodeOperandEncoding::Float64Bits => {
                        let Some(end) = cursor.checked_add(8) else {
                            return Err("p-code operand offset overflow".into());
                        };
                        let Some(bytes) = line.raw_bytes.get(cursor..end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        let bits = u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        operands.push(if matches!(encoding, PCodeOperandEncoding::QuadWord64) {
                            DecodedPCodeOperand::QuadWord64(bits)
                        } else {
                            DecodedPCodeOperand::Float64Bits(bits)
                        });
                        cursor = end;
                    }
                    PCodeOperandEncoding::BytesPrefixedByWord {
                        pad_odd_payload_to_even,
                    } => {
                        let Some(length_end) = cursor.checked_add(2) else {
                            return Err("p-code payload length offset overflow".into());
                        };
                        let Some(length_bytes) = line.raw_bytes.get(cursor..length_end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        let length =
                            u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
                        cursor = length_end;
                        let Some(payload_end) = cursor.checked_add(length) else {
                            return Err("p-code payload offset overflow".into());
                        };
                        let Some(payload) = line.raw_bytes.get(cursor..payload_end) else {
                            issue = Some(PCodeDecodeIssueKind::TruncatedOperand);
                            break;
                        };
                        operands.push(DecodedPCodeOperand::Bytes(payload.to_vec()));
                        cursor = payload_end;
                        if *pad_odd_payload_to_even && length & 1 != 0 {
                            let Some(padded_end) = cursor.checked_add(1) else {
                                return Err("p-code payload padding offset overflow".into());
                            };
                            if line.raw_bytes.get(cursor..padded_end).is_none() {
                                issue = Some(PCodeDecodeIssueKind::TruncatedPayloadPadding);
                                break;
                            }
                            cursor = padded_end;
                        }
                    }
                }
            }
            let instruction_complete = issue.is_none();
            decoded_line.instructions.push(DecodedPCodeInstruction {
                source_line: line.source_line,
                line_offset: instruction_start,
                cache_offset: line
                    .cache_offset
                    .and_then(|offset| offset.checked_add(instruction_start)),
                header_word,
                opcode,
                operation_type,
                mnemonic: Some(definition.mnemonic.clone()),
                operands,
                complete: instruction_complete,
            });
            report.instruction_count += 1;
            if let Some(kind) = issue {
                decoded_line.complete = false;
                decoded_line.issues.push(PCodeDecodeIssue {
                    source_line: line.source_line,
                    line_offset: instruction_start,
                    cache_offset: line
                        .cache_offset
                        .and_then(|offset| offset.checked_add(instruction_start)),
                    kind,
                    raw_header_word: Some(header_word),
                });
                report.complete = false;
                if matches!(
                    kind,
                    PCodeDecodeIssueKind::TruncatedOperand
                        | PCodeDecodeIssueKind::TruncatedPayloadPadding
                ) {
                    report.truncated = true;
                }
                break;
            }
        }
        report.lines.push(decoded_line);
    }
    Ok(report)
}

/// Apply a caller-supplied semantic specification to a decoded p-code report.
///
/// This performs bounded abstract stack evaluation only. It does not resolve
/// Office build-specific identifiers, aliases, COM calls, or branch targets;
/// unresolved values and control transfers are retained explicitly.
pub fn analyze_pcode_semantics(
    report: &PCodeDecodeReport,
    schema: &PCodeSemanticSchema,
    max_steps: usize,
) -> Result<PCodeSemanticReport, String> {
    schema.validate()?;
    if schema.id.is_empty() || schema.id.len() > 128 {
        return Err("p-code semantic schema id must contain 1 to 128 bytes".into());
    }
    if schema.max_stack == 0 || schema.max_stack > 4096 {
        return Err("p-code semantic schema max_stack must be between 1 and 4096".into());
    }
    if schema.definitions.is_empty() || schema.definitions.len() > 4096 {
        return Err("p-code semantic schema must contain 1 to 4096 definitions".into());
    }
    if max_steps == 0 {
        return Err("p-code semantic step limit must be greater than zero".into());
    }
    let mut definitions = HashMap::new();
    for definition in &schema.definitions {
        if definition.actions.len() > 128 {
            return Err(format!(
                "opcode 0x{:04x} exceeds the 128-action semantic limit",
                definition.opcode
            ));
        }
        let key = (definition.opcode, definition.operation_type);
        if definitions.insert(key, definition).is_some() {
            return Err(format!(
                "duplicate p-code semantic definition for opcode 0x{:04x} and operation type {:?}",
                definition.opcode, definition.operation_type
            ));
        }
    }

    let mut output = PCodeSemanticReport {
        schema_id: schema.id.clone(),
        schema_status: PCodeSchemaStatus::CallerSuppliedUnverified,
        steps: Vec::new(),
        unknown_value_count: 0,
        unknown_instruction_count: 0,
        stack_underflow_count: 0,
        complete: report.complete,
        truncated: false,
    };
    let mut stack = Vec::new();
    let mut locals = BTreeMap::<u64, PCodeSemanticValue>::new();
    for line in &report.lines {
        for instruction in &line.instructions {
            if output.steps.len() >= max_steps {
                output.complete = false;
                output.truncated = true;
                return Ok(output);
            }
            let definition = definitions
                .get(&(instruction.opcode, Some(instruction.operation_type)))
                .or_else(|| definitions.get(&(instruction.opcode, None)))
                .copied();
            let step = apply_decoded_instruction_semantics(
                instruction,
                definition,
                &mut stack,
                &mut locals,
                schema.max_stack,
            );
            match step.status {
                PCodeSemanticStepStatus::UnknownValue => output.unknown_value_count += 1,
                PCodeSemanticStepStatus::UnknownInstruction => {
                    output.unknown_instruction_count += 1
                }
                PCodeSemanticStepStatus::StackUnderflow => output.stack_underflow_count += 1,
                PCodeSemanticStepStatus::Applied => {}
            }
            if !instruction.complete
                || matches!(
                    step.status,
                    PCodeSemanticStepStatus::UnknownInstruction
                        | PCodeSemanticStepStatus::UnknownValue
                        | PCodeSemanticStepStatus::StackUnderflow
                )
            {
                output.complete = false;
            }
            output.steps.push(step);
        }
    }
    Ok(output)
}

fn apply_decoded_instruction_semantics(
    instruction: &DecodedPCodeInstruction,
    definition: Option<&PCodeSemanticDefinition>,
    stack: &mut Vec<PCodeSemanticValue>,
    locals: &mut BTreeMap<u64, PCodeSemanticValue>,
    max_stack: usize,
) -> PCodeSemanticStep {
    let stack_before = stack.clone();
    let locals_before = locals_snapshot(locals);
    let Some(definition) = definition else {
        return PCodeSemanticStep {
            source_line: instruction.source_line,
            line_offset: instruction.line_offset,
            opcode: instruction.opcode,
            operation_type: instruction.operation_type,
            mnemonic: instruction.mnemonic.clone(),
            stack_before,
            stack_after: stack.clone(),
            locals_before,
            locals_after: locals_snapshot(locals),
            control_transfer: PCodeSemanticControlTransfer::None,
            status: PCodeSemanticStepStatus::UnknownInstruction,
        };
    };
    let mut status = PCodeSemanticStepStatus::Applied;
    let mut control_transfer = PCodeSemanticControlTransfer::None;
    for action in &definition.actions {
        status = merge_semantic_status(
            status,
            apply_semantic_action(
                action,
                &instruction.operands,
                stack,
                locals,
                max_stack,
                &mut control_transfer,
            ),
        );
    }
    PCodeSemanticStep {
        source_line: instruction.source_line,
        line_offset: instruction.line_offset,
        opcode: instruction.opcode,
        operation_type: instruction.operation_type,
        mnemonic: instruction.mnemonic.clone(),
        stack_before,
        stack_after: stack.clone(),
        locals_before,
        locals_after: locals_snapshot(locals),
        control_transfer,
        status,
    }
}

/// Explore bounded abstract p-code paths using caller-supplied branch actions.
/// A relative branch is followed only when its target matches a decoded
/// instruction address; invalid or unknown targets remain on the fall-through
/// path and mark that path incomplete. This does not infer Office control-flow
/// encodings or resolve calls across procedures.
pub fn analyze_pcode_semantic_paths(
    report: &PCodeDecodeReport,
    schema: &PCodeSemanticSchema,
    max_paths: usize,
    max_steps: usize,
    branch_base: PCodeBranchBase,
) -> Result<PCodeSemanticPathReport, String> {
    schema.validate()?;
    if schema.id.is_empty() || schema.id.len() > 128 {
        return Err("p-code semantic schema id must contain 1 to 128 bytes".into());
    }
    if schema.max_stack == 0 || schema.max_stack > 4096 {
        return Err("p-code semantic schema max_stack must be between 1 and 4096".into());
    }
    if schema.definitions.is_empty() || schema.definitions.len() > 4096 {
        return Err("p-code semantic schema must contain 1 to 4096 definitions".into());
    }
    if max_paths == 0 || max_steps == 0 {
        return Err("p-code semantic path limits must be greater than zero".into());
    }
    let mut definitions = HashMap::new();
    for definition in &schema.definitions {
        if definition.actions.len() > 128 {
            return Err(format!(
                "opcode 0x{:04x} exceeds the 128-action semantic limit",
                definition.opcode
            ));
        }
        let key = (definition.opcode, definition.operation_type);
        if definitions.insert(key, definition).is_some() {
            return Err(format!(
                "duplicate p-code semantic definition for opcode 0x{:04x} and operation type {:?}",
                definition.opcode, definition.operation_type
            ));
        }
    }
    let instructions = report
        .lines
        .iter()
        .flat_map(|line| line.instructions.iter().cloned())
        .collect::<Vec<_>>();
    let mut cache_addresses = HashMap::<usize, usize>::new();
    let mut line_addresses = HashMap::<(usize, usize), usize>::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if let Some(address) = instruction.cache_offset {
            cache_addresses.entry(address).or_insert(index);
        }
        line_addresses
            .entry((instruction.source_line, instruction.line_offset))
            .or_insert(index);
    }

    #[derive(Clone)]
    struct State {
        pc: usize,
        stack: Vec<PCodeSemanticValue>,
        locals: BTreeMap<u64, PCodeSemanticValue>,
        steps: Vec<PCodeSemanticStep>,
        visited: HashSet<usize>,
        complete: bool,
    }

    let mut queue = VecDeque::new();
    queue.push_back(State {
        pc: 0,
        stack: Vec::new(),
        locals: BTreeMap::new(),
        steps: Vec::new(),
        visited: HashSet::new(),
        complete: report.complete,
    });
    let mut paths = Vec::new();
    let mut truncated = false;
    let mut unknown_value_count = 0usize;
    let mut unknown_instruction_count = 0usize;
    let mut stack_underflow_count = 0usize;
    while let Some(mut state) = queue.pop_front() {
        if state.steps.len() >= max_steps {
            truncated = true;
            paths.push(PCodeSemanticPath {
                path_index: paths.len(),
                steps: state.steps,
                complete: false,
                truncated: true,
                termination: PCodeSemanticPathTermination::StepLimit,
            });
            continue;
        }
        if state.pc >= instructions.len() {
            paths.push(PCodeSemanticPath {
                path_index: paths.len(),
                steps: state.steps,
                complete: state.complete,
                truncated: false,
                termination: PCodeSemanticPathTermination::EndOfStream,
            });
            continue;
        }
        if !state.visited.insert(state.pc) {
            paths.push(PCodeSemanticPath {
                path_index: paths.len(),
                steps: state.steps,
                complete: false,
                truncated: false,
                termination: PCodeSemanticPathTermination::LoopBound,
            });
            continue;
        }
        let instruction = &instructions[state.pc];
        let definition = definitions
            .get(&(instruction.opcode, Some(instruction.operation_type)))
            .or_else(|| definitions.get(&(instruction.opcode, None)))
            .copied();
        let step = apply_decoded_instruction_semantics(
            instruction,
            definition,
            &mut state.stack,
            &mut state.locals,
            schema.max_stack,
        );
        let status = step.status;
        match status {
            PCodeSemanticStepStatus::UnknownValue => unknown_value_count += 1,
            PCodeSemanticStepStatus::UnknownInstruction => unknown_instruction_count += 1,
            PCodeSemanticStepStatus::StackUnderflow => stack_underflow_count += 1,
            PCodeSemanticStepStatus::Applied => {}
        }
        let transfer = step.control_transfer.clone();
        state.steps.push(step);
        if !instruction.complete
            || matches!(
                status,
                PCodeSemanticStepStatus::UnknownInstruction
                    | PCodeSemanticStepStatus::UnknownValue
                    | PCodeSemanticStepStatus::StackUnderflow
            )
        {
            state.complete = false;
        }
        if status == PCodeSemanticStepStatus::UnknownInstruction {
            paths.push(PCodeSemanticPath {
                path_index: paths.len(),
                steps: state.steps,
                complete: false,
                truncated: false,
                termination: PCodeSemanticPathTermination::UnknownInstruction,
            });
            continue;
        }
        match transfer {
            PCodeSemanticControlTransfer::Return(_) => {
                paths.push(PCodeSemanticPath {
                    path_index: paths.len(),
                    steps: state.steps,
                    complete: state.complete,
                    truncated: false,
                    termination: PCodeSemanticPathTermination::Return,
                });
            }
            PCodeSemanticControlTransfer::BranchRelative(value) => {
                let fallthrough = state.pc.saturating_add(1);
                let branch_target = semantic_branch_target(
                    &instructions,
                    state.pc,
                    &value,
                    branch_base,
                    &cache_addresses,
                    &line_addresses,
                );
                let Some(branch_target) = branch_target else {
                    state.complete = false;
                    state.pc = fallthrough;
                    queue.push_back(state);
                    continue;
                };
                if paths.len().saturating_add(queue.len()).saturating_add(2) > max_paths {
                    truncated = true;
                    paths.push(PCodeSemanticPath {
                        path_index: paths.len(),
                        steps: state.steps,
                        complete: false,
                        truncated: true,
                        termination: PCodeSemanticPathTermination::StepLimit,
                    });
                    continue;
                }
                let mut branch_state = state.clone();
                branch_state.pc = branch_target;
                state.pc = fallthrough;
                queue.push_back(branch_state);
                queue.push_back(state);
            }
            PCodeSemanticControlTransfer::ConditionalBranchRelative { target, condition } => {
                let fallthrough = state.pc.saturating_add(1);
                let branch_target = semantic_branch_target(
                    &instructions,
                    state.pc,
                    &target,
                    branch_base,
                    &cache_addresses,
                    &line_addresses,
                );
                let Some(branch_target) = branch_target else {
                    state.complete = false;
                    state.pc = fallthrough;
                    queue.push_back(state);
                    continue;
                };
                let condition = semantic_condition_value(&condition);
                if condition == Some(false) {
                    state.pc = fallthrough;
                    queue.push_back(state);
                    continue;
                }
                if condition == Some(true) {
                    state.pc = branch_target;
                    queue.push_back(state);
                    continue;
                }
                if paths.len().saturating_add(queue.len()).saturating_add(2) > max_paths {
                    truncated = true;
                    paths.push(PCodeSemanticPath {
                        path_index: paths.len(),
                        steps: state.steps,
                        complete: false,
                        truncated: true,
                        termination: PCodeSemanticPathTermination::StepLimit,
                    });
                    continue;
                }
                let mut branch_state = state.clone();
                branch_state.pc = branch_target;
                state.pc = fallthrough;
                queue.push_back(branch_state);
                queue.push_back(state);
            }
            PCodeSemanticControlTransfer::None | PCodeSemanticControlTransfer::Call { .. } => {
                state.pc = state.pc.saturating_add(1);
                queue.push_back(state);
            }
        }
    }
    Ok(PCodeSemanticPathReport {
        schema_id: schema.id.clone(),
        schema_status: PCodeSchemaStatus::CallerSuppliedUnverified,
        complete: report.complete && !truncated && paths.iter().all(|path| path.complete),
        truncated,
        unknown_value_count,
        unknown_instruction_count,
        stack_underflow_count,
        paths,
    })
}

fn semantic_branch_target(
    instructions: &[DecodedPCodeInstruction],
    pc: usize,
    value: &PCodeSemanticValue,
    branch_base: PCodeBranchBase,
    cache_addresses: &HashMap<usize, usize>,
    line_addresses: &HashMap<(usize, usize), usize>,
) -> Option<usize> {
    let delta = match value {
        PCodeSemanticValue::Integer(value) => *value,
        _ => return None,
    };
    let instruction = instructions.get(pc)?;
    let cache_base = instruction.cache_offset.map(|offset| offset as i64);
    let line_base = instruction.line_offset as i64;
    let base = match branch_base {
        PCodeBranchBase::InstructionStart => cache_base.unwrap_or(line_base),
        PCodeBranchBase::NextInstruction => {
            let next = instructions
                .get(pc + 1)
                .filter(|next| next.source_line == instruction.source_line);
            next.and_then(|next| next.cache_offset.map(|offset| offset as i64))
                .or_else(|| cache_base.map(|offset| offset.saturating_add(2)))
                .unwrap_or_else(|| line_base.saturating_add(2))
        }
    };
    let target = base.checked_add(delta)?;
    if target < 0 {
        return None;
    }
    if cache_base.is_some() {
        cache_addresses.get(&(target as usize)).copied()
    } else {
        line_addresses
            .get(&(instruction.source_line, target as usize))
            .copied()
    }
}

fn merge_semantic_status(
    current: PCodeSemanticStepStatus,
    next: PCodeSemanticStepStatus,
) -> PCodeSemanticStepStatus {
    match (current, next) {
        (PCodeSemanticStepStatus::StackUnderflow, _)
        | (_, PCodeSemanticStepStatus::StackUnderflow) => PCodeSemanticStepStatus::StackUnderflow,
        (PCodeSemanticStepStatus::UnknownValue, _) | (_, PCodeSemanticStepStatus::UnknownValue) => {
            PCodeSemanticStepStatus::UnknownValue
        }
        (PCodeSemanticStepStatus::UnknownInstruction, _)
        | (_, PCodeSemanticStepStatus::UnknownInstruction) => {
            PCodeSemanticStepStatus::UnknownInstruction
        }
        _ => PCodeSemanticStepStatus::Applied,
    }
}

fn apply_semantic_action(
    action: &PCodeSemanticAction,
    operands: &[DecodedPCodeOperand],
    stack: &mut Vec<PCodeSemanticValue>,
    locals: &mut BTreeMap<u64, PCodeSemanticValue>,
    max_stack: usize,
    control_transfer: &mut PCodeSemanticControlTransfer,
) -> PCodeSemanticStepStatus {
    match action {
        PCodeSemanticAction::PushOperand { operand_index } => {
            let value = operands
                .get(*operand_index)
                .map(semantic_value_from_operand)
                .unwrap_or(PCodeSemanticValue::Unknown);
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            if stack.len() < max_stack {
                stack.push(value);
            } else {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            status
        }
        PCodeSemanticAction::PushErrorOperand { operand_index } => {
            let value = operands
                .get(*operand_index)
                .and_then(semantic_integer_operand)
                .and_then(|value| i32::try_from(value).ok())
                .map(PCodeSemanticValue::Error)
                .unwrap_or(PCodeSemanticValue::Unknown);
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            if stack.len() >= max_stack {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            stack.push(value);
            status
        }
        PCodeSemanticAction::PushStringOperand {
            operand_index,
            encoding,
        } => {
            let value = operands
                .get(*operand_index)
                .and_then(|operand| semantic_string_from_operand(operand, *encoding))
                .map(PCodeSemanticValue::String)
                .unwrap_or(PCodeSemanticValue::Unknown);
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            if stack.len() >= max_stack {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            stack.push(value);
            status
        }
        PCodeSemanticAction::PushObjectOperand { operand_index } => {
            let value = operands
                .get(*operand_index)
                .and_then(semantic_integer_operand)
                .and_then(|value| u64::try_from(value).ok())
                .map(PCodeSemanticValue::Object)
                .unwrap_or(PCodeSemanticValue::Unknown);
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            if stack.len() >= max_stack {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            stack.push(value);
            status
        }
        PCodeSemanticAction::PushLiteral(value) => {
            if stack.len() < max_stack {
                stack.push(value.clone());
                if *value == PCodeSemanticValue::Unknown {
                    PCodeSemanticStepStatus::UnknownValue
                } else {
                    PCodeSemanticStepStatus::Applied
                }
            } else {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                PCodeSemanticStepStatus::UnknownValue
            }
        }
        PCodeSemanticAction::LoadSlot { slot } => {
            let value = locals
                .get(slot)
                .cloned()
                .unwrap_or(PCodeSemanticValue::Unknown);
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            if stack.len() >= max_stack {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            stack.push(value);
            status
        }
        PCodeSemanticAction::StoreSlot { slot } => {
            let Some(value) = stack.pop() else {
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            locals.insert(*slot, value);
            status
        }
        PCodeSemanticAction::Unary(operator) => {
            let Some(value) = stack.pop() else {
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let result = apply_unary(*operator, value);
            let status = if result == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            stack.push(result);
            status
        }
        PCodeSemanticAction::Binary(operator) => {
            let Some(right) = stack.pop() else {
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let Some(left) = stack.pop() else {
                stack.push(right);
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let result = apply_binary(*operator, left, right);
            let status = if result == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            stack.push(result);
            status
        }
        PCodeSemanticAction::Drop => {
            if stack.pop().is_some() {
                PCodeSemanticStepStatus::Applied
            } else {
                PCodeSemanticStepStatus::StackUnderflow
            }
        }
        PCodeSemanticAction::Duplicate => {
            let Some(value) = stack.last().cloned() else {
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            if stack.len() >= max_stack {
                return PCodeSemanticStepStatus::UnknownValue;
            }
            let status = if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            stack.push(value);
            status
        }
        PCodeSemanticAction::ArrayIndex => {
            let Some(index) = stack.pop() else {
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let Some(array) = stack.pop() else {
                stack.push(index);
                return PCodeSemanticStepStatus::StackUnderflow;
            };
            let result = match (array, index) {
                (PCodeSemanticValue::Array(values), PCodeSemanticValue::Integer(index))
                    if index >= 0 && (index as usize) < values.len() =>
                {
                    values[index as usize].clone()
                }
                _ => PCodeSemanticValue::Unknown,
            };
            let status = if result == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            };
            stack.push(result);
            status
        }
        PCodeSemanticAction::BranchRelative { operand_index } => {
            let value = operands
                .get(*operand_index)
                .map(semantic_value_from_operand)
                .unwrap_or(PCodeSemanticValue::Unknown);
            *control_transfer = PCodeSemanticControlTransfer::BranchRelative(value.clone());
            if value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            }
        }
        PCodeSemanticAction::BranchRelativeIf { operand_index } => {
            let condition = stack.pop().unwrap_or(PCodeSemanticValue::Unknown);
            let value = operands
                .get(*operand_index)
                .map(semantic_value_from_operand)
                .unwrap_or(PCodeSemanticValue::Unknown);
            *control_transfer = PCodeSemanticControlTransfer::ConditionalBranchRelative {
                target: value.clone(),
                condition: condition.clone(),
            };
            if value == PCodeSemanticValue::Unknown
                || semantic_condition_value(&condition).is_none()
            {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            }
        }
        PCodeSemanticAction::Call {
            target_operand_index,
            argument_count,
            returns_value,
        } => {
            if *argument_count > stack.len() {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::StackUnderflow;
            }
            for _ in 0..*argument_count {
                stack.pop();
            }
            let target = target_operand_index
                .and_then(|index| operands.get(index))
                .map(semantic_value_from_operand);
            let target_known = target
                .as_ref()
                .is_some_and(|value| *value != PCodeSemanticValue::Unknown);
            *control_transfer = PCodeSemanticControlTransfer::Call {
                target: target.clone(),
                returns_value: *returns_value,
            };
            if *returns_value {
                if stack.len() >= max_stack {
                    stack.clear();
                    stack.push(PCodeSemanticValue::Unknown);
                    return PCodeSemanticStepStatus::UnknownValue;
                }
                stack.push(PCodeSemanticValue::Unknown);
                // A call's return value is intentionally opaque even when the
                // target encoding is known; the caller-supplied schema may
                // describe the call boundary, but it cannot prove the
                // callee's body here.
                PCodeSemanticStepStatus::UnknownValue
            } else if target_known {
                PCodeSemanticStepStatus::Applied
            } else {
                PCodeSemanticStepStatus::UnknownValue
            }
        }
        PCodeSemanticAction::CallKnownReturn {
            target_operand_index,
            argument_count,
            return_value,
        } => {
            if *argument_count > stack.len() {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::StackUnderflow;
            }
            for _ in 0..*argument_count {
                stack.pop();
            }
            let target = target_operand_index
                .and_then(|index| operands.get(index))
                .map(semantic_value_from_operand);
            let target_known = target
                .as_ref()
                .is_none_or(|value| *value != PCodeSemanticValue::Unknown);
            *control_transfer = PCodeSemanticControlTransfer::Call {
                target: target.clone(),
                returns_value: true,
            };
            if stack.len() >= max_stack {
                stack.clear();
                stack.push(PCodeSemanticValue::Unknown);
                return PCodeSemanticStepStatus::UnknownValue;
            }
            stack.push(return_value.clone());
            if !target_known || *return_value == PCodeSemanticValue::Unknown {
                PCodeSemanticStepStatus::UnknownValue
            } else {
                PCodeSemanticStepStatus::Applied
            }
        }
        PCodeSemanticAction::Return { has_value } => {
            if *has_value {
                let Some(value) = stack.pop() else {
                    return PCodeSemanticStepStatus::StackUnderflow;
                };
                *control_transfer = PCodeSemanticControlTransfer::Return(Some(value));
            } else {
                *control_transfer = PCodeSemanticControlTransfer::Return(None);
            }
            PCodeSemanticStepStatus::Applied
        }
        PCodeSemanticAction::InvalidateStack => {
            for value in stack.iter_mut() {
                *value = PCodeSemanticValue::Unknown;
            }
            PCodeSemanticStepStatus::UnknownValue
        }
    }
}

fn locals_snapshot(locals: &BTreeMap<u64, PCodeSemanticValue>) -> Vec<(u64, PCodeSemanticValue)> {
    locals
        .iter()
        .map(|(slot, value)| (*slot, value.clone()))
        .collect()
}

fn semantic_value_from_operand(operand: &DecodedPCodeOperand) -> PCodeSemanticValue {
    match operand {
        DecodedPCodeOperand::Byte8(value) => PCodeSemanticValue::Integer(i64::from(*value)),
        DecodedPCodeOperand::Word16(value) => PCodeSemanticValue::Integer(i64::from(*value)),
        DecodedPCodeOperand::SignedWord16(value) => PCodeSemanticValue::Integer(i64::from(*value)),
        DecodedPCodeOperand::DoubleWord32(value) => PCodeSemanticValue::Integer(i64::from(*value)),
        DecodedPCodeOperand::SignedDoubleWord32(value) => {
            PCodeSemanticValue::Integer(i64::from(*value))
        }
        DecodedPCodeOperand::QuadWord64(value) => i64::try_from(*value)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        DecodedPCodeOperand::Float64Bits(value) => PCodeSemanticValue::Float64Bits(*value),
        DecodedPCodeOperand::Bytes(value) => PCodeSemanticValue::Bytes(value.clone()),
    }
}

fn semantic_integer_operand(operand: &DecodedPCodeOperand) -> Option<i64> {
    match semantic_value_from_operand(operand) {
        PCodeSemanticValue::Integer(value) => Some(value),
        _ => None,
    }
}

fn semantic_string_from_operand(
    operand: &DecodedPCodeOperand,
    encoding: PCodeStringEncoding,
) -> Option<String> {
    let DecodedPCodeOperand::Bytes(bytes) = operand else {
        return None;
    };
    if bytes.len() > 16 * 1024 {
        return None;
    }
    match encoding {
        PCodeStringEncoding::Utf8 => std::str::from_utf8(bytes).ok().map(str::to_owned),
        PCodeStringEncoding::Utf16Le if bytes.len() % 2 == 0 => {
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .ok()
        }
        PCodeStringEncoding::Utf16Le => None,
    }
}

fn semantic_condition_value(value: &PCodeSemanticValue) -> Option<bool> {
    match value {
        PCodeSemanticValue::Boolean(value) => Some(*value),
        PCodeSemanticValue::Integer(value) => Some(*value != 0),
        _ => None,
    }
}

fn apply_unary(operator: PCodeUnaryOperator, value: PCodeSemanticValue) -> PCodeSemanticValue {
    match (operator, value) {
        (PCodeUnaryOperator::Negate, PCodeSemanticValue::Integer(value)) => value
            .checked_neg()
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (PCodeUnaryOperator::Negate, PCodeSemanticValue::Float64Bits(value)) => {
            let value = f64::from_bits(value);
            if value.is_finite() {
                PCodeSemanticValue::Float64Bits((-value).to_bits())
            } else {
                PCodeSemanticValue::Unknown
            }
        }
        (PCodeUnaryOperator::Not, PCodeSemanticValue::Boolean(value)) => {
            PCodeSemanticValue::Boolean(!value)
        }
        (PCodeUnaryOperator::Not, PCodeSemanticValue::Integer(value)) => {
            PCodeSemanticValue::Integer(!value)
        }
        (PCodeUnaryOperator::Not, PCodeSemanticValue::Null) => PCodeSemanticValue::Null,
        (PCodeUnaryOperator::Not, PCodeSemanticValue::Empty) => PCodeSemanticValue::Integer(!0),
        (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Object(_)) => {
            PCodeSemanticValue::Boolean(true)
        }
        (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Array(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Null)
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Empty)
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Integer(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Boolean(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::String(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Float64Bits(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Bytes(_))
        | (PCodeUnaryOperator::IsObject, PCodeSemanticValue::Error(_)) => {
            PCodeSemanticValue::Boolean(false)
        }
        (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Array(_)) => {
            PCodeSemanticValue::Boolean(true)
        }
        (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Object(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Null)
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Empty)
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Integer(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Boolean(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::String(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Float64Bits(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Bytes(_))
        | (PCodeUnaryOperator::IsArray, PCodeSemanticValue::Error(_)) => {
            PCodeSemanticValue::Boolean(false)
        }
        (PCodeUnaryOperator::ArrayLength, PCodeSemanticValue::Array(values)) => {
            PCodeSemanticValue::Integer(values.len() as i64)
        }
        _ => PCodeSemanticValue::Unknown,
    }
}

fn apply_binary(
    operator: PCodeBinaryOperator,
    left: PCodeSemanticValue,
    right: PCodeSemanticValue,
) -> PCodeSemanticValue {
    if let (PCodeSemanticValue::Error(left), PCodeSemanticValue::Error(right)) = (&left, &right) {
        return match operator {
            PCodeBinaryOperator::Equal => PCodeSemanticValue::Boolean(left == right),
            PCodeBinaryOperator::NotEqual => PCodeSemanticValue::Boolean(left != right),
            _ => PCodeSemanticValue::Unknown,
        };
    }
    if matches!(&left, PCodeSemanticValue::Error(_))
        || matches!(&right, PCodeSemanticValue::Error(_))
    {
        return PCodeSemanticValue::Unknown;
    }
    if let (PCodeSemanticValue::Object(left), PCodeSemanticValue::Object(right)) = (&left, &right) {
        return match operator {
            PCodeBinaryOperator::Equal => PCodeSemanticValue::Boolean(left == right),
            PCodeBinaryOperator::NotEqual => PCodeSemanticValue::Boolean(left != right),
            _ => PCodeSemanticValue::Unknown,
        };
    }
    if matches!(&left, PCodeSemanticValue::Null) || matches!(&right, PCodeSemanticValue::Null) {
        return match (&left, &right, operator) {
            (
                PCodeSemanticValue::Boolean(false),
                PCodeSemanticValue::Null,
                PCodeBinaryOperator::And,
            )
            | (
                PCodeSemanticValue::Null,
                PCodeSemanticValue::Boolean(false),
                PCodeBinaryOperator::And,
            ) => PCodeSemanticValue::Boolean(false),
            (
                PCodeSemanticValue::Boolean(true),
                PCodeSemanticValue::Null,
                PCodeBinaryOperator::Or,
            )
            | (
                PCodeSemanticValue::Null,
                PCodeSemanticValue::Boolean(true),
                PCodeBinaryOperator::Or,
            ) => PCodeSemanticValue::Boolean(true),
            _ => PCodeSemanticValue::Null,
        };
    }
    if matches!(&left, PCodeSemanticValue::Empty) || matches!(&right, PCodeSemanticValue::Empty) {
        let left = if matches!(&left, PCodeSemanticValue::Empty) {
            PCodeSemanticValue::Integer(0)
        } else {
            left
        };
        let right = if matches!(&right, PCodeSemanticValue::Empty) {
            PCodeSemanticValue::Integer(0)
        } else {
            right
        };
        return apply_binary(operator, left, right);
    }
    let left_is_float = matches!(&left, PCodeSemanticValue::Float64Bits(_));
    let right_is_float = matches!(&right, PCodeSemanticValue::Float64Bits(_));
    if let (Some(left), Some(right)) = (
        semantic_numeric_float_value(&left),
        semantic_numeric_float_value(&right),
    ) && (left_is_float || right_is_float)
    {
        return match operator {
            PCodeBinaryOperator::Add => semantic_float_result(left + right),
            PCodeBinaryOperator::Subtract => semantic_float_result(left - right),
            PCodeBinaryOperator::Multiply => semantic_float_result(left * right),
            PCodeBinaryOperator::Divide if right != 0.0 => semantic_float_result(left / right),
            PCodeBinaryOperator::Modulo if right != 0.0 => semantic_float_result(left % right),
            PCodeBinaryOperator::Equal => PCodeSemanticValue::Boolean(left == right),
            PCodeBinaryOperator::NotEqual => PCodeSemanticValue::Boolean(left != right),
            PCodeBinaryOperator::LessThan => PCodeSemanticValue::Boolean(left < right),
            PCodeBinaryOperator::LessOrEqual => PCodeSemanticValue::Boolean(left <= right),
            PCodeBinaryOperator::GreaterThan => PCodeSemanticValue::Boolean(left > right),
            PCodeBinaryOperator::GreaterOrEqual => PCodeSemanticValue::Boolean(left >= right),
            _ => PCodeSemanticValue::Unknown,
        };
    }
    if let (PCodeSemanticValue::String(left), PCodeSemanticValue::String(right)) = (&left, &right) {
        return match operator {
            PCodeBinaryOperator::Equal => PCodeSemanticValue::Boolean(left == right),
            PCodeBinaryOperator::NotEqual => PCodeSemanticValue::Boolean(left != right),
            PCodeBinaryOperator::LessThan => PCodeSemanticValue::Boolean(left < right),
            PCodeBinaryOperator::LessOrEqual => PCodeSemanticValue::Boolean(left <= right),
            PCodeBinaryOperator::GreaterThan => PCodeSemanticValue::Boolean(left > right),
            PCodeBinaryOperator::GreaterOrEqual => PCodeSemanticValue::Boolean(left >= right),
            PCodeBinaryOperator::Concat if left.len().saturating_add(right.len()) <= 16 * 1024 => {
                PCodeSemanticValue::String(format!("{left}{right}"))
            }
            _ => PCodeSemanticValue::Unknown,
        };
    }
    match (operator, left, right) {
        (
            PCodeBinaryOperator::Add,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => left
            .checked_add(right)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (
            PCodeBinaryOperator::Subtract,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => left
            .checked_sub(right)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (
            PCodeBinaryOperator::Multiply,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => left
            .checked_mul(right)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (
            PCodeBinaryOperator::Divide,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) if right != 0 => left
            .checked_div(right)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (
            PCodeBinaryOperator::Modulo,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) if right != 0 => left
            .checked_rem(right)
            .map(PCodeSemanticValue::Integer)
            .unwrap_or(PCodeSemanticValue::Unknown),
        (PCodeBinaryOperator::Equal, left, right)
            if left != PCodeSemanticValue::Unknown && right != PCodeSemanticValue::Unknown =>
        {
            PCodeSemanticValue::Boolean(left == right)
        }
        (PCodeBinaryOperator::NotEqual, left, right)
            if left != PCodeSemanticValue::Unknown && right != PCodeSemanticValue::Unknown =>
        {
            PCodeSemanticValue::Boolean(left != right)
        }
        (
            PCodeBinaryOperator::LessThan,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Boolean(left < right),
        (
            PCodeBinaryOperator::LessOrEqual,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Boolean(left <= right),
        (
            PCodeBinaryOperator::GreaterThan,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Boolean(left > right),
        (
            PCodeBinaryOperator::GreaterOrEqual,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Boolean(left >= right),
        (
            PCodeBinaryOperator::And,
            PCodeSemanticValue::Boolean(left),
            PCodeSemanticValue::Boolean(right),
        ) => PCodeSemanticValue::Boolean(left && right),
        (
            PCodeBinaryOperator::Or,
            PCodeSemanticValue::Boolean(left),
            PCodeSemanticValue::Boolean(right),
        ) => PCodeSemanticValue::Boolean(left || right),
        (
            PCodeBinaryOperator::Xor,
            PCodeSemanticValue::Boolean(left),
            PCodeSemanticValue::Boolean(right),
        ) => PCodeSemanticValue::Boolean(left ^ right),
        (
            PCodeBinaryOperator::Eqv,
            PCodeSemanticValue::Boolean(left),
            PCodeSemanticValue::Boolean(right),
        ) => PCodeSemanticValue::Boolean(left == right),
        (
            PCodeBinaryOperator::Imp,
            PCodeSemanticValue::Boolean(left),
            PCodeSemanticValue::Boolean(right),
        ) => PCodeSemanticValue::Boolean(!left || right),
        (
            PCodeBinaryOperator::And,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Integer(left & right),
        (
            PCodeBinaryOperator::Or,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Integer(left | right),
        (
            PCodeBinaryOperator::Xor,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Integer(left ^ right),
        (
            PCodeBinaryOperator::Eqv,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Integer(!(left ^ right)),
        (
            PCodeBinaryOperator::Imp,
            PCodeSemanticValue::Integer(left),
            PCodeSemanticValue::Integer(right),
        ) => PCodeSemanticValue::Integer(!left | right),
        (
            PCodeBinaryOperator::Concat,
            PCodeSemanticValue::Bytes(mut left),
            PCodeSemanticValue::Bytes(right),
        ) if left.len().saturating_add(right.len()) <= 16 * 1024 => {
            left.extend(right);
            PCodeSemanticValue::Bytes(left)
        }
        (
            PCodeBinaryOperator::Concat,
            PCodeSemanticValue::String(mut left),
            PCodeSemanticValue::String(right),
        ) if left.len().saturating_add(right.len()) <= 16 * 1024 => {
            left.push_str(&right);
            PCodeSemanticValue::String(left)
        }
        _ => PCodeSemanticValue::Unknown,
    }
}

fn semantic_float_value(value: &PCodeSemanticValue) -> Option<f64> {
    match value {
        PCodeSemanticValue::Float64Bits(bits) => {
            let value = f64::from_bits(*bits);
            value.is_finite().then_some(value)
        }
        _ => None,
    }
}

fn semantic_numeric_float_value(value: &PCodeSemanticValue) -> Option<f64> {
    match value {
        PCodeSemanticValue::Integer(value) => Some(*value as f64),
        PCodeSemanticValue::Float64Bits(_) => semantic_float_value(value),
        _ => None,
    }
}

fn semantic_float_result(value: f64) -> PCodeSemanticValue {
    if value.is_finite() {
        PCodeSemanticValue::Float64Bits(value.to_bits())
    } else {
        PCodeSemanticValue::Unknown
    }
}

fn valid_shifted_bit_field(mask: u16, shift: u8) -> bool {
    if mask == 0 || shift >= 16 {
        return false;
    }
    if shift > 0 && mask & ((1u16 << shift) - 1) != 0 {
        return false;
    }
    let shifted_mask = (mask >> shift) as u32;
    shifted_mask != 0 && shifted_mask & (shifted_mask + 1) == 0
}

/// Extract validated source-line slices from the VBA7-observed p-code layout.
/// The caller must select the profile; the generic MS-OVBA cache is opaque.
pub fn inspect_vba7_line_map(
    cache: &[u8],
    profile: PCodeLayoutProfile,
    max_lines: usize,
) -> Result<Option<PCodeLineMap>, String> {
    let mut search = 0usize;
    let mut found = None;
    while search + 1 < cache.len() {
        let Some(relative) = cache[search..].windows(2).position(|w| w == [0xFE, 0xCA]) else {
            break;
        };
        let cafe = search + relative;
        search = cafe + 2;
        if let Some(map) = try_line_map(cache, cafe, profile, max_lines)? {
            if found.is_some() {
                return Err(
                    "multiple plausible CAFE line maps found in the selected cache profile".into(),
                );
            }
            found = Some(map);
        }
    }
    Ok(found)
}

fn try_line_map(
    cache: &[u8],
    cafe: usize,
    profile: PCodeLayoutProfile,
    max_lines: usize,
) -> Result<Option<PCodeLineMap>, String> {
    // Two profile-specific bytes follow CAFE before the u16 source-line count.
    let Some(count_offset) = cafe.checked_add(4) else {
        return Ok(None);
    };
    let Some(count_bytes) = cache.get(count_offset..count_offset + 2) else {
        return Ok(None);
    };
    let profile_header_raw = [cache[cafe + 2], cache[cafe + 3]];
    let line_count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]) as usize;
    if line_count == 0 || line_count > max_lines {
        return Ok(None);
    }
    let directory_offset = count_offset + 2;
    let Some(directory_bytes) = line_count.checked_mul(12) else {
        return Ok(None);
    };
    let Some(directory_end) = directory_offset.checked_add(directory_bytes) else {
        return Ok(None);
    };
    let Some(code_table_offset) = directory_end.checked_add(10) else {
        return Ok(None);
    };
    if code_table_offset > cache.len() {
        return Ok(None);
    }

    let mut lines = Vec::with_capacity(line_count);
    let mut total = 0usize;
    let mut previous_line_end = 0usize;
    for source_line in 0..line_count {
        let record = directory_offset + source_line * 12;
        let record_prefix_raw = cache[record..record + 4].try_into().unwrap();
        let line_length = u16::from_le_bytes([cache[record + 4], cache[record + 5]]);
        let record_middle_raw = cache[record + 6..record + 8].try_into().unwrap();
        let relative_offset =
            u32::from_le_bytes(cache[record + 8..record + 12].try_into().unwrap());
        if relative_offset == u32::MAX || line_length == 0 {
            lines.push(PCodeLineSegment {
                source_line,
                line_length,
                record_prefix_raw,
                record_middle_raw,
                relative_code_offset_raw: relative_offset,
                cache_offset: None,
                raw_bytes: Vec::new(),
                raw_word_count: 0,
                has_partial_word: false,
            });
            continue;
        }
        let Some(start) = code_table_offset.checked_add(relative_offset as usize) else {
            return Ok(None);
        };
        let Some(end) = start.checked_add(line_length as usize) else {
            return Ok(None);
        };
        let Some(bytes) = cache.get(start..end) else {
            return Ok(None);
        };
        let relative_end = (relative_offset as usize)
            .checked_add(line_length as usize)
            .ok_or("p-code line offset overflow")?;
        if (relative_offset as usize) < previous_line_end {
            return Ok(None);
        }
        previous_line_end = relative_end;
        total = total
            .checked_add(bytes.len())
            .ok_or("p-code byte count overflow")?;
        lines.push(PCodeLineSegment {
            source_line,
            line_length,
            record_prefix_raw,
            record_middle_raw,
            relative_code_offset_raw: relative_offset,
            cache_offset: Some(start),
            raw_bytes: bytes.to_vec(),
            raw_word_count: bytes.len() / 2,
            has_partial_word: bytes.len() & 1 != 0,
        });
    }
    Ok(Some(PCodeLineMap {
        profile,
        cafe_offset: cafe,
        profile_header_raw,
        line_count,
        directory_offset,
        code_table_offset,
        code_bytes_total: total,
        lines,
        mnemonics_decoded: false,
    }))
}

pub fn inspect_project_stream(stream: &[u8]) -> Result<ProjectCacheInspection, String> {
    if stream.len() < 7 {
        return Err("_VBA_PROJECT stream is shorter than its 7-byte header".into());
    }
    let reserved1 = u16::from_le_bytes([stream[0], stream[1]]);
    let version = u16::from_le_bytes([stream[2], stream[3]]);
    let reserved2 = stream[4];
    let reserved3 = u16::from_le_bytes([stream[5], stream[6]]);
    let cache = &stream[7..];
    Ok(ProjectCacheInspection {
        reserved1,
        version,
        reserved2,
        reserved3,
        cache_length: cache.len(),
        fingerprint_fnv1a64: fingerprint_fnv1a64(cache),
        header_well_formed: reserved1 == 0x61CC && reserved2 == 0,
        pcode_disassembled: false,
    })
}

pub fn inspect_module_stream(
    stream: &[u8],
    text_offset: u32,
) -> Result<ModuleCacheInspection, String> {
    let offset = text_offset as usize;
    if offset > stream.len() {
        return Err("MODULEOFFSET lies outside the module stream".into());
    }
    Ok(ModuleCacheInspection {
        declared_text_offset: text_offset,
        cache_length: offset,
        fingerprint_fnv1a64: fingerprint_fnv1a64(&stream[..offset]),
        source_container_signature_valid: stream.get(offset) == Some(&0x01),
        pcode_disassembled: false,
    })
}

pub fn fingerprint_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_line_map(raw_bytes: &[u8]) -> PCodeLineMap {
        PCodeLineMap {
            profile: PCodeLayoutProfile::Vba7Observed,
            cafe_offset: 0,
            profile_header_raw: [0, 0],
            line_count: 1,
            directory_offset: 6,
            code_table_offset: 28,
            code_bytes_total: raw_bytes.len(),
            lines: vec![PCodeLineSegment {
                source_line: 0,
                line_length: raw_bytes.len() as u16,
                record_prefix_raw: [0; 4],
                record_middle_raw: [0; 2],
                relative_code_offset_raw: 0,
                cache_offset: Some(100),
                raw_bytes: raw_bytes.to_vec(),
                raw_word_count: raw_bytes.len() / 2,
                has_partial_word: raw_bytes.len() & 1 != 0,
            }],
            mnemonics_decoded: false,
        }
    }

    fn synthetic_word_schema() -> PCodeInstructionSchema {
        PCodeInstructionSchema {
            id: "synthetic-test-schema".into(),
            opcode_mask: 0x03ff,
            opcode_shift: 0,
            operation_type_mask: 0xfc00,
            operation_type_shift: 10,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "NoOperands".into(),
                    operands: Vec::new(),
                },
                PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "WordOperand".into(),
                    operands: vec![PCodeOperandEncoding::Word16],
                },
                PCodeOpcodeDefinition {
                    opcode: 3,
                    operation_type: None,
                    mnemonic: "TextPayload".into(),
                    operands: vec![PCodeOperandEncoding::BytesPrefixedByWord {
                        pad_odd_payload_to_even: true,
                    }],
                },
            ],
        }
    }

    #[test]
    fn reads_project_header_but_never_claims_to_decode_pcode() {
        let stream = [0xcc, 0x61, 0xff, 0xff, 0, 1, 0, 0xaa, 0xbb];
        let report = inspect_project_stream(&stream).unwrap();
        assert_eq!(report.version, 0xffff);
        assert_eq!(report.cache_length, 2);
        assert!(report.header_well_formed);
        assert!(!report.pcode_disassembled);
    }

    #[test]
    fn validates_caller_instruction_schema_without_a_line_map() {
        let schema = synthetic_word_schema();
        assert!(schema.validate().is_ok());
        let mut invalid = schema.clone();
        invalid.definitions[0].mnemonic.clear();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn validates_caller_semantic_schema_without_a_line_map() {
        let schema = PCodeSemanticSchema {
            id: "semantic-validation".into(),
            max_stack: 4,
            definitions: vec![PCodeSemanticDefinition {
                opcode: 1,
                operation_type: None,
                actions: vec![PCodeSemanticAction::Drop],
            }],
        };
        assert!(schema.validate().is_ok());
        let duplicate = PCodeSemanticSchema {
            definitions: vec![schema.definitions[0].clone(), schema.definitions[0].clone()],
            ..schema
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn validates_line_map_metadata_before_decoding() {
        let mut line_map = synthetic_line_map(&[0x01, 0x00]);
        assert!(line_map.validate().is_ok());
        line_map.code_bytes_total = 0;
        assert!(line_map.validate().is_err());
        let mut missing_line = synthetic_line_map(&[0x01, 0x00]);
        missing_line.lines.push(PCodeLineSegment {
            source_line: 1,
            line_length: 12,
            record_prefix_raw: [0; 4],
            record_middle_raw: [0; 2],
            relative_code_offset_raw: u32::MAX,
            cache_offset: None,
            raw_bytes: Vec::new(),
            raw_word_count: 0,
            has_partial_word: false,
        });
        missing_line.line_count = 2;
        assert!(missing_line.validate().is_ok());
    }

    #[test]
    fn checks_module_cache_boundary_and_source_signature() {
        let report = inspect_module_stream(&[0xaa, 0xbb, 1, 0, 0], 2).unwrap();
        assert_eq!(report.cache_length, 2);
        assert!(report.source_container_signature_valid);
        assert!(!report.pcode_disassembled);
        assert!(inspect_module_stream(&[0], 2).is_err());
    }

    #[test]
    fn validates_line_map_and_preserves_raw_pcode_without_decoding_it() {
        let mut cache = vec![0u8; 2 + 2 + 2 + 12 * 2 + 10 + 6];
        cache[0..2].copy_from_slice(&[0xfe, 0xca]);
        cache[2..4].copy_from_slice(&[0x12, 0x34]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[6..10].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        cache[12..14].copy_from_slice(&[0x55, 0x66]);
        cache[6 + 4..6 + 6].copy_from_slice(&4u16.to_le_bytes());
        cache[6 + 8..6 + 12].copy_from_slice(&0u32.to_le_bytes());
        cache[18 + 4..18 + 6].copy_from_slice(&2u16.to_le_bytes());
        cache[18 + 8..18 + 12].copy_from_slice(&4u32.to_le_bytes());
        let code = 40;
        cache[code..code + 6].copy_from_slice(&[0x05, 0x00, 0xAA, 0xBB, 0x09, 0x04]);
        let map = inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 100)
            .unwrap()
            .unwrap();
        assert_eq!(map.line_count, 2);
        assert_eq!(map.profile_header_raw, [0x12, 0x34]);
        assert_eq!(map.lines[0].record_prefix_raw, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(map.lines[0].record_middle_raw, [0x55, 0x66]);
        assert_eq!(map.lines[0].relative_code_offset_raw, 0);
        assert_eq!(map.lines[1].relative_code_offset_raw, 4);
        assert_eq!(map.lines[0].raw_word_count, 2);
        assert_eq!(map.lines[1].raw_bytes, [0x09, 0x04]);
        assert!(!map.mnemonics_decoded);
    }

    #[test]
    fn accepts_independently_published_line_record_shapes() {
        // The 12-byte records are the published examples in the provenance document.
        let mut cache = vec![0u8; 40 + 0x10 + 6];
        cache[..2].copy_from_slice(&[0xfe, 0xca]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[6..18].copy_from_slice(&[
            0x00, 0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        ]);
        cache[18..30].copy_from_slice(&[
            0x42, 0xa1, 0x08, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x00, 0x00,
        ]);
        let map = inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 10)
            .unwrap()
            .unwrap();
        assert_eq!(map.lines[0].cache_offset, None);
        assert_eq!(map.lines[0].relative_code_offset_raw, u32::MAX);
        assert_eq!(map.lines[0].record_prefix_raw, [0x00, 0x80, 0x09, 0x00]);
        assert_eq!(map.lines[1].line_length, 6);
        assert_eq!(map.lines[1].cache_offset, Some(40 + 0x10));
    }

    #[test]
    fn rejects_ambiguous_multiple_line_map_candidates() {
        let mut cache = vec![0u8; 2 + 2 + 2 + 12 * 2 + 10 + 6];
        cache[0..2].copy_from_slice(&[0xfe, 0xca]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[10..12].copy_from_slice(&4u16.to_le_bytes());
        cache[14..18].copy_from_slice(&0u32.to_le_bytes());
        cache[22..24].copy_from_slice(&2u16.to_le_bytes());
        cache[26..30].copy_from_slice(&4u32.to_le_bytes());
        cache[40..46].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        let second = cache.clone();
        cache.extend_from_slice(&second);
        assert!(inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 100).is_err());
    }

    #[test]
    fn rejects_invalid_line_ranges_and_handles_every_truncated_prefix() {
        let mut cache = vec![0u8; 40 + 6];
        cache[..2].copy_from_slice(&[0xfe, 0xca]);
        cache[4..6].copy_from_slice(&2u16.to_le_bytes());
        cache[10..12].copy_from_slice(&4u16.to_le_bytes());
        cache[14..18].copy_from_slice(&0u32.to_le_bytes());
        cache[22..24].copy_from_slice(&2u16.to_le_bytes());
        cache[26..30].copy_from_slice(&4u32.to_le_bytes());
        cache[40..46].copy_from_slice(&[1, 2, 3, 4, 5, 6]);

        assert!(
            inspect_vba7_line_map(&cache, PCodeLayoutProfile::Vba7Observed, 1)
                .unwrap()
                .is_none()
        );
        for end in 0..cache.len() {
            assert!(
                inspect_vba7_line_map(&cache[..end], PCodeLayoutProfile::Vba7Observed, 2)
                    .unwrap()
                    .is_none(),
                "accepted truncated cache prefix ending at {end}"
            );
        }

        let mut overlapping = cache.clone();
        overlapping[26..30].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            inspect_vba7_line_map(&overlapping, PCodeLayoutProfile::Vba7Observed, 2)
                .unwrap()
                .is_none()
        );

        let mut out_of_bounds = cache;
        out_of_bounds[26..30].copy_from_slice(&5u32.to_le_bytes());
        assert!(
            inspect_vba7_line_map(&out_of_bounds, PCodeLayoutProfile::Vba7Observed, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decodes_raw_words_only_with_a_caller_supplied_schema() {
        let bytes = [
            0x01, 0x04, // opcode 1; operation type 1
            0x02, 0x08, 0x34, 0x12, // opcode 2; operation type 2; u16 operand
            0x03, 0x00, 0x03, 0x00, b'a', b'b', b'c', 0x00, // length-prefixed odd payload
        ];
        let report = decode_pcode_lines_with_schema(
            &synthetic_line_map(&bytes),
            &synthetic_word_schema(),
            10,
        )
        .unwrap();
        assert_eq!(report.schema_id, "synthetic-test-schema");
        assert_eq!(
            report.schema_status,
            PCodeSchemaStatus::CallerSuppliedUnverified
        );
        assert!(report.complete);
        assert!(!report.truncated);
        assert_eq!(report.instruction_count, 3);
        let instructions = &report.lines[0].instructions;
        assert_eq!(instructions[0].mnemonic.as_deref(), Some("NoOperands"));
        assert_eq!(instructions[0].operation_type, 1);
        assert_eq!(instructions[0].cache_offset, Some(100));
        assert_eq!(instructions[1].opcode, 2);
        assert_eq!(instructions[1].operation_type, 2);
        assert_eq!(
            instructions[1].operands,
            [DecodedPCodeOperand::Word16(0x1234)]
        );
        assert_eq!(instructions[2].mnemonic.as_deref(), Some("TextPayload"));
        assert_eq!(
            instructions[2].operands,
            [DecodedPCodeOperand::Bytes(vec![b'a', b'b', b'c'])]
        );
        assert!(instructions.iter().all(|instruction| instruction.complete));
    }

    #[test]
    fn caller_schema_decoder_reports_unknown_truncated_and_limited_words() {
        let schema = synthetic_word_schema();
        let unknown =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x04, 0x00]), &schema, 10)
                .unwrap();
        assert!(!unknown.complete);
        assert_eq!(
            unknown.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::UnknownOpcode
        );
        assert_eq!(unknown.lines[0].instructions[0].mnemonic, None);

        let truncated =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x02, 0x00]), &schema, 10)
                .unwrap();
        assert!(!truncated.complete);
        assert!(truncated.truncated);
        assert_eq!(
            truncated.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::TruncatedOperand
        );
        assert!(!truncated.lines[0].instructions[0].complete);

        let partial_header =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x01, 0x00, 0xff]), &schema, 10)
                .unwrap();
        assert!(!partial_header.complete);
        assert!(partial_header.truncated);
        assert_eq!(partial_header.instruction_count, 1);
        assert_eq!(
            partial_header.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::TruncatedHeader
        );

        let limited = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0x01, 0x00]),
            &schema,
            1,
        )
        .unwrap();
        assert!(limited.truncated);
        assert!(!limited.complete);
        assert_eq!(limited.instruction_count, 1);
        assert_eq!(
            limited.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::InstructionLimit
        );
    }

    #[test]
    fn caller_schema_decoder_rejects_ambiguous_or_malformed_profiles() {
        let line_map = synthetic_line_map(&[0x01, 0x00]);
        let mut duplicate = synthetic_word_schema();
        duplicate.definitions.push(duplicate.definitions[0].clone());
        assert!(decode_pcode_lines_with_schema(&line_map, &duplicate, 10).is_err());

        let mut operation_type_without_field = synthetic_word_schema();
        operation_type_without_field.definitions[0].operation_type = Some(1);
        operation_type_without_field.operation_type_mask = 0;
        assert!(
            decode_pcode_lines_with_schema(&line_map, &operation_type_without_field, 10).is_err()
        );

        let mut operation_type_out_of_range = synthetic_word_schema();
        operation_type_out_of_range.definitions[0].operation_type = Some(64);
        assert!(
            decode_pcode_lines_with_schema(&line_map, &operation_type_out_of_range, 10).is_err()
        );

        let mut overlapping = synthetic_word_schema();
        overlapping.operation_type_mask = 0x0003;
        assert!(decode_pcode_lines_with_schema(&line_map, &overlapping, 10).is_err());

        let mut invalid_shift = synthetic_word_schema();
        invalid_shift.opcode_shift = 1;
        assert!(decode_pcode_lines_with_schema(&line_map, &invalid_shift, 10).is_err());

        let mut sparse_opcode_mask = synthetic_word_schema();
        sparse_opcode_mask.opcode_mask = 0x000a;
        sparse_opcode_mask.opcode_shift = 1;
        assert!(decode_pcode_lines_with_schema(&line_map, &sparse_opcode_mask, 10).is_err());

        let mut sparse_operation_type_mask = synthetic_word_schema();
        sparse_operation_type_mask.operation_type_mask = 0xf400;
        sparse_operation_type_mask.operation_type_shift = 10;
        assert!(
            decode_pcode_lines_with_schema(&line_map, &sparse_operation_type_mask, 10).is_err()
        );

        assert!(decode_pcode_lines_with_schema(&line_map, &synthetic_word_schema(), 0).is_err());
    }

    #[test]
    fn caller_schema_selects_operand_layout_by_operation_type() {
        let schema = PCodeInstructionSchema {
            id: "synthetic-operation-type-schema".into(),
            opcode_mask: 0x000f,
            opcode_shift: 0,
            operation_type_mask: 0x00f0,
            operation_type_shift: 4,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: Some(1),
                    mnemonic: "WordVariant".into(),
                    operands: vec![PCodeOperandEncoding::Word16],
                },
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: Some(2),
                    mnemonic: "DoubleWordVariant".into(),
                    operands: vec![PCodeOperandEncoding::DoubleWord32],
                },
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "GenericVariant".into(),
                    operands: Vec::new(),
                },
            ],
        };
        let bytes = [
            0x11, 0x00, 0x34, 0x12, // opcode 1, operation type 1, word operand
            0x21, 0x00, 0x78, 0x56, 0x34, 0x12, // type 2, double-word operand
            0x31, 0x00, // type 3 falls back to generic definition
        ];
        let report =
            decode_pcode_lines_with_schema(&synthetic_line_map(&bytes), &schema, 10).unwrap();
        assert!(report.complete);
        let instructions = &report.lines[0].instructions;
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic.as_deref(), Some("WordVariant"));
        assert_eq!(
            instructions[0].operands,
            [DecodedPCodeOperand::Word16(0x1234)]
        );
        assert_eq!(
            instructions[1].mnemonic.as_deref(),
            Some("DoubleWordVariant")
        );
        assert_eq!(
            instructions[1].operands,
            [DecodedPCodeOperand::DoubleWord32(0x12345678)]
        );
        assert_eq!(instructions[2].operation_type, 3);
        assert_eq!(instructions[2].mnemonic.as_deref(), Some("GenericVariant"));

        let exact_only = PCodeInstructionSchema {
            definitions: schema.definitions[..2].to_vec(),
            ..schema
        };
        let unmatched_type =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x31, 0x00]), &exact_only, 10)
                .unwrap();
        assert!(!unmatched_type.complete);
        assert_eq!(
            unmatched_type.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::UnknownOperationType
        );
    }

    #[test]
    fn caller_schema_decodes_signed_and_wide_scalar_operands_as_raw_values() {
        let schema = PCodeInstructionSchema {
            id: "synthetic-scalar-operands".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 4,
                operation_type: None,
                mnemonic: "OpaqueScalars".into(),
                operands: vec![
                    PCodeOperandEncoding::Byte8,
                    PCodeOperandEncoding::SignedWord16,
                    PCodeOperandEncoding::SignedDoubleWord32,
                    PCodeOperandEncoding::QuadWord64,
                    PCodeOperandEncoding::Float64Bits,
                ],
            }],
        };
        let raw = [
            0x04, 0x00, // instruction word
            0xfe, // byte
            0x00, 0x80, // signed i16 minimum
            0x00, 0x00, 0x00, 0x80, // signed i32 minimum
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // u64
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, // f64 1.0 bits
        ];
        let report =
            decode_pcode_lines_with_schema(&synthetic_line_map(&raw), &schema, 10).unwrap();
        assert!(report.complete);
        assert_eq!(
            report.lines[0].instructions[0].operands,
            vec![
                DecodedPCodeOperand::Byte8(0xfe),
                DecodedPCodeOperand::SignedWord16(i16::MIN),
                DecodedPCodeOperand::SignedDoubleWord32(i32::MIN),
                DecodedPCodeOperand::QuadWord64(0x0102_0304_0506_0708),
                DecodedPCodeOperand::Float64Bits(0x3ff0_0000_0000_0000),
            ]
        );

        let truncated_schema = PCodeInstructionSchema {
            id: "synthetic-truncated-float".into(),
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 5,
                operation_type: None,
                mnemonic: "FloatOperand".into(),
                operands: vec![PCodeOperandEncoding::Float64Bits],
            }],
            ..schema
        };
        let truncated = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x05, 0x00, 0x00, 0x00]),
            &truncated_schema,
            10,
        )
        .unwrap();
        assert!(!truncated.complete);
        assert_eq!(
            truncated.lines[0].issues[0].kind,
            PCodeDecodeIssueKind::TruncatedOperand
        );
    }

    #[test]
    fn applies_caller_semantic_stack_spec_to_decoded_instructions() {
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[
                0x02, 0x00, 0x07, 0x00, // push 7
                0x02, 0x00, 0x05, 0x00, // push 5
                0x01, 0x00, // add
            ]),
            &synthetic_word_schema(),
            10,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-semantic-stack".into(),
                max_stack: 8,
                definitions: vec![
                    PCodeSemanticDefinition {
                        opcode: 1,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::Binary(PCodeBinaryOperator::Add)],
                    },
                    PCodeSemanticDefinition {
                        opcode: 2,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::PushOperand { operand_index: 0 }],
                    },
                ],
            },
            10,
        )
        .unwrap();
        assert!(semantic.complete);
        assert!(!semantic.truncated);
        assert_eq!(semantic.steps.len(), 3);
        assert_eq!(
            semantic.steps[2].stack_after,
            vec![PCodeSemanticValue::Integer(12)]
        );
        assert_eq!(semantic.steps[2].status, PCodeSemanticStepStatus::Applied);
    }

    #[test]
    fn semantic_analysis_retains_unknown_instructions_and_stack_underflow() {
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00]),
            &synthetic_word_schema(),
            10,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-underflow".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Binary(PCodeBinaryOperator::Add)],
                }],
            },
            10,
        )
        .unwrap();
        assert!(!semantic.complete);
        assert_eq!(
            semantic.steps[0].status,
            PCodeSemanticStepStatus::StackUnderflow
        );
        assert_eq!(semantic.stack_underflow_count, 1);

        let unknown = analyze_pcode_semantics(
            &decode_pcode_lines_with_schema(
                &synthetic_line_map(&[0x09, 0x00]),
                &synthetic_word_schema(),
                10,
            )
            .unwrap(),
            &PCodeSemanticSchema {
                id: "synthetic-unknown".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Drop],
                }],
            },
            10,
        )
        .unwrap();
        assert!(!unknown.complete);
        assert_eq!(
            unknown.steps[0].status,
            PCodeSemanticStepStatus::UnknownInstruction
        );
        assert_eq!(unknown.unknown_instruction_count, 1);
    }

    #[test]
    fn semantic_call_without_return_is_applied_when_target_is_known() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-call".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "CallVoid".into(),
                operands: vec![PCodeOperandEncoding::Word16],
            }],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0x07, 0x00]),
            &decode_schema,
            4,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-call".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Call {
                        target_operand_index: Some(0),
                        argument_count: 0,
                        returns_value: false,
                    }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(semantic.steps[0].status, PCodeSemanticStepStatus::Applied);
        assert_eq!(
            semantic.steps[0].control_transfer,
            PCodeSemanticControlTransfer::Call {
                target: Some(PCodeSemanticValue::Integer(7)),
                returns_value: false,
            }
        );
    }

    #[test]
    fn semantic_call_known_return_pushes_schema_summary() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-call-summary".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "CallSummary".into(),
                operands: Vec::new(),
            }],
        };
        let decoded =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x01, 0x00]), &decode_schema, 4)
                .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-call-summary".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::CallKnownReturn {
                        target_operand_index: None,
                        argument_count: 0,
                        return_value: PCodeSemanticValue::Integer(42),
                    }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(
            semantic.steps[0].stack_after,
            vec![PCodeSemanticValue::Integer(42)]
        );
        assert_eq!(semantic.steps[0].status, PCodeSemanticStepStatus::Applied);
    }

    #[test]
    fn semantic_call_known_return_keeps_unknown_target_incomplete() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-call-unknown-target".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "CallSummary".into(),
                operands: vec![PCodeOperandEncoding::QuadWord64],
            }],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            &decode_schema,
            4,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-call-unknown-target".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::CallKnownReturn {
                        target_operand_index: Some(0),
                        argument_count: 0,
                        return_value: PCodeSemanticValue::Integer(42),
                    }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(!semantic.complete);
        assert_eq!(
            semantic.steps[0].status,
            PCodeSemanticStepStatus::UnknownValue
        );
        assert_eq!(
            semantic.steps[0].stack_after,
            vec![PCodeSemanticValue::Integer(42)]
        );
    }

    #[test]
    fn semantic_call_unknown_return_marks_report_incomplete() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-call-unknown-return".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "Call".into(),
                operands: Vec::new(),
            }],
        };
        let decoded =
            decode_pcode_lines_with_schema(&synthetic_line_map(&[0x01, 0x00]), &decode_schema, 4)
                .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-call-unknown-return".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Call {
                        target_operand_index: None,
                        argument_count: 0,
                        returns_value: true,
                    }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(!semantic.complete);
        assert_eq!(
            semantic.steps[0].status,
            PCodeSemanticStepStatus::UnknownValue
        );
        assert_eq!(
            semantic.steps[0].stack_after,
            vec![PCodeSemanticValue::Unknown]
        );
    }

    #[test]
    fn semantic_error_operand_preserves_vba_error_code() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-error-operand".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "PushError".into(),
                operands: vec![PCodeOperandEncoding::SignedWord16],
            }],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0x0d, 0x00]),
            &decode_schema,
            4,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-error-operand".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::PushErrorOperand { operand_index: 0 }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(
            semantic.steps[0].stack_after,
            vec![PCodeSemanticValue::Error(13)]
        );
    }

    #[test]
    fn semantic_schema_can_model_object_and_array_predicates_explicitly() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-object-array".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "PushObject".into(),
                    operands: vec![PCodeOperandEncoding::Word16],
                },
                PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "IsObject".into(),
                    operands: vec![],
                },
                PCodeOpcodeDefinition {
                    opcode: 3,
                    operation_type: None,
                    mnemonic: "PushArray".into(),
                    operands: vec![],
                },
                PCodeOpcodeDefinition {
                    opcode: 4,
                    operation_type: None,
                    mnemonic: "IsArray".into(),
                    operands: vec![],
                },
            ],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[1, 0, 7, 0, 2, 0, 3, 0, 4, 0]),
            &decode_schema,
            8,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-object-array".into(),
                max_stack: 4,
                definitions: vec![
                    PCodeSemanticDefinition {
                        opcode: 1,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::PushObjectOperand { operand_index: 0 }],
                    },
                    PCodeSemanticDefinition {
                        opcode: 2,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::Unary(PCodeUnaryOperator::IsObject)],
                    },
                    PCodeSemanticDefinition {
                        opcode: 3,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::PushLiteral(PCodeSemanticValue::Array(
                            vec![PCodeSemanticValue::Integer(1)],
                        ))],
                    },
                    PCodeSemanticDefinition {
                        opcode: 4,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::Unary(PCodeUnaryOperator::IsArray)],
                    },
                ],
            },
            8,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(
            semantic.steps[1].stack_after,
            vec![PCodeSemanticValue::Boolean(true)]
        );
        assert_eq!(
            semantic.steps[3].stack_after,
            vec![
                PCodeSemanticValue::Boolean(true),
                PCodeSemanticValue::Boolean(true)
            ]
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Equal,
                PCodeSemanticValue::Object(7),
                PCodeSemanticValue::Object(7),
            ),
            PCodeSemanticValue::Boolean(true)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Equal,
                PCodeSemanticValue::Object(7),
                PCodeSemanticValue::Object(8),
            ),
            PCodeSemanticValue::Boolean(false)
        );
        assert_eq!(
            apply_unary(
                PCodeUnaryOperator::ArrayLength,
                PCodeSemanticValue::Array(vec![
                    PCodeSemanticValue::Integer(1),
                    PCodeSemanticValue::Integer(2),
                ]),
            ),
            PCodeSemanticValue::Integer(2)
        );
        let mut stack = vec![
            PCodeSemanticValue::Array(vec![PCodeSemanticValue::Integer(9)]),
            PCodeSemanticValue::Integer(0),
        ];
        let mut locals = BTreeMap::new();
        let mut transfer = PCodeSemanticControlTransfer::None;
        assert_eq!(
            apply_semantic_action(
                &PCodeSemanticAction::ArrayIndex,
                &[],
                &mut stack,
                &mut locals,
                4,
                &mut transfer,
            ),
            PCodeSemanticStepStatus::Applied
        );
        assert_eq!(stack, vec![PCodeSemanticValue::Integer(9)]);
    }

    #[test]
    fn semantic_analysis_tracks_caller_defined_local_slots() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-slots".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "LoadSlot".into(),
                    operands: Vec::new(),
                },
                PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "StoreSlot".into(),
                    operands: vec![PCodeOperandEncoding::Word16],
                },
            ],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x02, 0x00, 0x07, 0x00, 0x01, 0x00]),
            &decode_schema,
            10,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-slots".into(),
                max_stack: 4,
                definitions: vec![
                    PCodeSemanticDefinition {
                        opcode: 1,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::LoadSlot { slot: 1 }],
                    },
                    PCodeSemanticDefinition {
                        opcode: 2,
                        operation_type: None,
                        actions: vec![
                            PCodeSemanticAction::PushOperand { operand_index: 0 },
                            PCodeSemanticAction::StoreSlot { slot: 1 },
                        ],
                    },
                ],
            },
            10,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(
            semantic.steps[1].stack_after,
            vec![PCodeSemanticValue::Integer(7)]
        );
        assert_eq!(
            semantic.steps[1].locals_after,
            vec![(1, PCodeSemanticValue::Integer(7))]
        );
    }

    #[test]
    fn semantic_path_analysis_splits_known_relative_branches() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-branch".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "Branch".into(),
                    operands: vec![PCodeOperandEncoding::SignedWord16],
                },
                PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "ReturnFallthrough".into(),
                    operands: Vec::new(),
                },
                PCodeOpcodeDefinition {
                    opcode: 3,
                    operation_type: None,
                    mnemonic: "ReturnTarget".into(),
                    operands: Vec::new(),
                },
            ],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0x06, 0x00, 0x02, 0x00, 0x03, 0x00]),
            &decode_schema,
            10,
        )
        .unwrap();
        let semantic_schema = PCodeSemanticSchema {
            id: "synthetic-branch".into(),
            max_stack: 4,
            definitions: vec![
                PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::BranchRelative { operand_index: 0 }],
                },
                PCodeSemanticDefinition {
                    opcode: 2,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Return { has_value: false }],
                },
                PCodeSemanticDefinition {
                    opcode: 3,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::Return { has_value: false }],
                },
            ],
        };
        let paths = analyze_pcode_semantic_paths(
            &decoded,
            &semantic_schema,
            4,
            8,
            PCodeBranchBase::InstructionStart,
        )
        .unwrap();
        assert!(paths.complete);
        assert!(!paths.truncated);
        assert_eq!(paths.paths.len(), 2);
        assert!(paths.paths.iter().all(|path| {
            path.complete && path.termination == PCodeSemanticPathTermination::Return
        }));
        assert!(paths.paths.iter().any(|path| {
            path.steps.last().and_then(|step| step.mnemonic.as_deref()) == Some("ReturnTarget")
        }));
    }

    #[test]
    fn semantic_path_analysis_selects_known_conditional_branch() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-conditional-branch".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![
                PCodeOpcodeDefinition {
                    opcode: 1,
                    operation_type: None,
                    mnemonic: "BranchIf".into(),
                    operands: vec![PCodeOperandEncoding::SignedWord16],
                },
                PCodeOpcodeDefinition {
                    opcode: 2,
                    operation_type: None,
                    mnemonic: "PushTrue".into(),
                    operands: Vec::new(),
                },
                PCodeOpcodeDefinition {
                    opcode: 3,
                    operation_type: None,
                    mnemonic: "ReturnFallthrough".into(),
                    operands: Vec::new(),
                },
                PCodeOpcodeDefinition {
                    opcode: 4,
                    operation_type: None,
                    mnemonic: "ReturnTarget".into(),
                    operands: Vec::new(),
                },
            ],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[
                0x02, 0x00, // push True
                0x01, 0x00, 0x06, 0x00, // target = offset 2 + 6 = 8
                0x03, 0x00, // fall-through
                0x04, 0x00, // target
            ]),
            &decode_schema,
            10,
        )
        .unwrap();
        let paths = analyze_pcode_semantic_paths(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-conditional-branch".into(),
                max_stack: 2,
                definitions: vec![
                    PCodeSemanticDefinition {
                        opcode: 1,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::BranchRelativeIf { operand_index: 0 }],
                    },
                    PCodeSemanticDefinition {
                        opcode: 2,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::PushLiteral(
                            PCodeSemanticValue::Boolean(true),
                        )],
                    },
                    PCodeSemanticDefinition {
                        opcode: 3,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::Return { has_value: false }],
                    },
                    PCodeSemanticDefinition {
                        opcode: 4,
                        operation_type: None,
                        actions: vec![PCodeSemanticAction::Return { has_value: false }],
                    },
                ],
            },
            4,
            8,
            PCodeBranchBase::InstructionStart,
        )
        .unwrap();
        assert!(paths.complete);
        assert_eq!(paths.paths.len(), 1);
        assert_eq!(
            paths.paths[0]
                .steps
                .last()
                .and_then(|step| step.mnemonic.as_deref()),
            Some("ReturnTarget")
        );
    }

    #[test]
    fn semantic_concat_keeps_bounded_byte_payloads() {
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Concat,
                PCodeSemanticValue::Bytes(b"left".to_vec()),
                PCodeSemanticValue::Bytes(b"right".to_vec()),
            ),
            PCodeSemanticValue::Bytes(b"leftright".to_vec())
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Concat,
                PCodeSemanticValue::Bytes(vec![0; 16 * 1024]),
                PCodeSemanticValue::Bytes(vec![1]),
            ),
            PCodeSemanticValue::Unknown
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Concat,
                PCodeSemanticValue::String("left".into()),
                PCodeSemanticValue::String("right".into()),
            ),
            PCodeSemanticValue::String("leftright".into())
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Xor,
                PCodeSemanticValue::Integer(0b1010),
                PCodeSemanticValue::Integer(0b0110),
            ),
            PCodeSemanticValue::Integer(0b1100)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Imp,
                PCodeSemanticValue::Boolean(true),
                PCodeSemanticValue::Boolean(false),
            ),
            PCodeSemanticValue::Boolean(false)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Add,
                PCodeSemanticValue::Float64Bits(1.5f64.to_bits()),
                PCodeSemanticValue::Float64Bits(2.25f64.to_bits()),
            ),
            PCodeSemanticValue::Float64Bits(3.75f64.to_bits())
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::GreaterThan,
                PCodeSemanticValue::Float64Bits(2.0f64.to_bits()),
                PCodeSemanticValue::Float64Bits(1.0f64.to_bits()),
            ),
            PCodeSemanticValue::Boolean(true)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Add,
                PCodeSemanticValue::Float64Bits(f64::NAN.to_bits()),
                PCodeSemanticValue::Float64Bits(1.0f64.to_bits()),
            ),
            PCodeSemanticValue::Unknown
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Multiply,
                PCodeSemanticValue::Integer(2),
                PCodeSemanticValue::Float64Bits(1.5f64.to_bits()),
            ),
            PCodeSemanticValue::Float64Bits(3.0f64.to_bits())
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::LessThan,
                PCodeSemanticValue::String("alpha".into()),
                PCodeSemanticValue::String("beta".into()),
            ),
            PCodeSemanticValue::Boolean(true)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Add,
                PCodeSemanticValue::Empty,
                PCodeSemanticValue::Integer(4),
            ),
            PCodeSemanticValue::Integer(4)
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Add,
                PCodeSemanticValue::Null,
                PCodeSemanticValue::Integer(4),
            ),
            PCodeSemanticValue::Null
        );
        assert_eq!(
            apply_binary(
                PCodeBinaryOperator::Equal,
                PCodeSemanticValue::Error(13),
                PCodeSemanticValue::Error(13),
            ),
            PCodeSemanticValue::Boolean(true)
        );
    }

    #[test]
    fn semantic_string_operand_uses_only_caller_selected_encoding() {
        let decode_schema = PCodeInstructionSchema {
            id: "synthetic-string-operand".into(),
            opcode_mask: 0xffff,
            opcode_shift: 0,
            operation_type_mask: 0,
            operation_type_shift: 0,
            definitions: vec![PCodeOpcodeDefinition {
                opcode: 1,
                operation_type: None,
                mnemonic: "StringOperand".into(),
                operands: vec![PCodeOperandEncoding::BytesPrefixedByWord {
                    pad_odd_payload_to_even: false,
                }],
            }],
        };
        let decoded = decode_pcode_lines_with_schema(
            &synthetic_line_map(&[0x01, 0x00, 0x05, 0x00, b'h', b'e', b'l', b'l', b'o']),
            &decode_schema,
            4,
        )
        .unwrap();
        let semantic = analyze_pcode_semantics(
            &decoded,
            &PCodeSemanticSchema {
                id: "synthetic-string-operand".into(),
                max_stack: 2,
                definitions: vec![PCodeSemanticDefinition {
                    opcode: 1,
                    operation_type: None,
                    actions: vec![PCodeSemanticAction::PushStringOperand {
                        operand_index: 0,
                        encoding: PCodeStringEncoding::Utf8,
                    }],
                }],
            },
            4,
        )
        .unwrap();
        assert!(semantic.complete);
        assert_eq!(
            semantic.steps[0].stack_after,
            vec![PCodeSemanticValue::String("hello".into())]
        );
        assert_eq!(
            semantic_string_from_operand(
                &DecodedPCodeOperand::Bytes(vec![0x53, 0x00, 0x30, 0x00]),
                PCodeStringEncoding::Utf16Le,
            ),
            Some("S0".into())
        );
    }
}
