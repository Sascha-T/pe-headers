export interface MZHeader {
    Magic: number, /// e_magic
    LastPageBytes: number, /// e_cblp
    PagesInFile: number, /// e_cp
    Relocations: number, /// e_crlc
    SizeOfHeader: number, /// e_cparhdr
    MinAlloc: number, /// e_minalloc
    MaxAlloc: number, /// e_maxalloc
    RegisterSS: number, /// e_ss,
    RegisterSP: number, /// e_sp
    Checksum: number, /// e_csum
    RegisterIP: number, /// e_ip
    RegisterCS: number, /// e_cs
    RelocationTableAddress: number, /// e_lfarlc
    OverlayNumber: number, /// e_ovno
    Reserved: number[], /// e_res
    OEMId: number, /// e_oemid
    OemInfo: number, /// e_oeminfo
    Reserved2: number[], /// e_res2
    PEHeaderAddress: number /// e_lfanew
}

export interface PEHeader {
    Magic: number,
    Machine: number,
    TimeStamp: number,
    SymbolTableAddress: number,
    SymbolCount: number,
    OptionalHeaderSize: number,
    Characteristics: number,
    Optional?: PEOptional,
    Sections: SectionHeader[]
}

export interface PEOptional {
    Magic: Bitness,
    MajorLinkerVersion: number,
    MinorLinkerVersion: number,
    CodeSize: number,
    InitializedDataSize: number,
    UninitializedDataSize: number,
    EntryPointAddress: number,
    CodeBase: number,
    DataBase: number,
    ImageBase: number,
    SectionAlignment: number,
    FileAlignment: number,
    MajorOperatingSystemVersion: number
    MinorOperatingSystemVersion: number,
    MajorImageVersion: number,
    MinorImageVersion: number,
    MajorSubsystemVersion: number,
    MinorSubsystemVersion: number,
    Win32VersionValue: number,
    ImageSize: number,
    HeaderSize: number,
    Checksum: number,
    Subsystem: number,
    Characteristics: number,
    StackReserveSize: number, // DW / QW
    StackCommitSize: number, // DW / QW
    HeapReserveSize: number, // DW / QW
    HeapCommitSize: number, // DW / QW
    LoaderFlags: number
    Directories: DirectoryEntry[]
}

export enum Bitness {
    BITS32 = 0x10b,
    BITS64 = 0x20b
}

export interface DirectoryEntry {
    RVA: number,
    Size: number,
    Present: boolean
}

export enum DirectoryIndices {
    EXPORT = 0x00,
    IMPORT = 0x01,
    RESOURCE = 0x02,
    EXCEPTION = 0x03,
    SECURITY = 0x04,
    RELOC = 0x05,
    DEBUG = 0x06,
    ARCH = 0x07,
    GLOBAL = 0x08,
    TLS = 0x09,
    LOAD = 0x0A,
    BOUND_IMPORT = 0x0B,
    IMPORT_ADDRESS = 0x0C,
    IMPORT_DELAY = 0x0D,
    NET_METADATA = 0x0E,
    RESERVED = 0x0F
}

export interface SectionHeader {
    Name: string,
    VirtualSize: number,
    VirtualAddress: number,
    RawDataSize: number,
    RawDataAddress: number,
    RelocationsAddress: number,
    LineNumbersAddress: number,
    RelocationsCount: number,
    LineNumbersCount: number,
    Characteristics: number
}

export interface Cor20Header {
    Size: number,
    MajorRuntimeVersion: number,
    MinorRuntimeVersion: number,
    MetadataRVA: number,
    MetadataSize: number,
    Flags: number,
    EntrypointToken: number,
    ResourcesRVA: number,
    ResourcesSize: number,
    StrongNameSignatureRVA: number,
    StrongNameSignatureSize: number,
    CodeManagerTableRVA: number,
    CodeManagerTableSize: number,
    VTableFixupsRVA: number,
    VTableFixupsSize: number,
    ExportAddressTableJumpRVA: number,
    ExportAddressTableJumpSize: number,
    ManagedNativeHeaderRVA: number,
    ManagedNativeHeaderSize: number
}

export interface MetadataHeader {
    Signature: number,
    MajorVersion: number,
    MinorVersion: number,
    Reserved: number,
    VersionString: string,
    Flags: number,
    Streams: StreamHeader[]
}

export interface StreamHeader {
    Offset: number,
    Size: number,
    Name: string
}
