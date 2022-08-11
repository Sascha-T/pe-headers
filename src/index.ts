import {
    Bitness,
    Cor20Header,
    DirectoryEntry,
    DirectoryIndices, MetadataHeader,
    MZHeader,
    PEHeader,
    PEOptional,
    SectionHeader, StreamHeader
} from "./types";

export function readMZHeader(inp: ArrayBuffer): MZHeader {
    let dv = new DataView(inp);

    let magic = dv.getUint16(0x00, true);
    if (magic != 0x5A4D)
        throw "MZ Header is invalid, expected 0x5A4D, got 0x" + magic.toString(16)
    let cblp = dv.getUint16(0x02, true);
    let cp = dv.getUint16(0x04, true);
    let crlc = dv.getUint16(0x06, true);
    let cparhrd = dv.getUint16(0x08, true);
    let minalloc = dv.getUint16(0x0A, true);
    let maxalloc = dv.getUint16(0x0C, true);
    let ss = dv.getUint16(0x0E, true);
    let sp = dv.getUint16(0x10, true);
    let csum = dv.getUint16(0x12, true);
    let ip = dv.getUint16(0x14, true);
    let cs = dv.getUint16(0x16, true);
    let lfarlc = dv.getUint16(0x18, true);
    let ovno = dv.getUint16(0x1A, true);
    let res = []
    for (let i = 0; i < 4; i++)
        res.push(dv.getUint16(0x1C + i * 2));
    let oemid = dv.getUint16(0x24, true);
    let oeminfo = dv.getUint16(0x26, true);
    let res2 = []
    for (let i = 0; i < 10; i++)
        res2.push(dv.getUint16(0x28 + i * 2));
    let lfanew = dv.getUint32(0x3C, true);
    return {
        Checksum: csum,
        LastPageBytes: cblp,
        Magic: magic,
        MaxAlloc: maxalloc,
        MinAlloc: minalloc,
        OEMId: oemid,
        OemInfo: oeminfo,
        OverlayNumber: ovno,
        PEHeaderAddress: lfanew,
        PagesInFile: cp,
        RegisterCS: cs,
        RegisterIP: ip,
        RegisterSP: sp,
        RegisterSS: ss,
        RelocationTableAddress: lfarlc,
        Relocations: crlc,
        Reserved: res,
        Reserved2: res2,
        SizeOfHeader: cparhrd
    }
}

export function readPEHeader(inp: ArrayBuffer, offset: number): PEHeader {
    let dv = new DataView(inp, offset);
    let magic = dv.getUint32(0x00, true);
    if (magic != 0x00004550)
        throw "Invalid PE Header signature, expected 0x4550, got: 0x" + magic.toString(16)
    let machine = dv.getUint16(0x04, true);
    let sections = dv.getUint16(0x06, true);
    let timestamp = dv.getUint32(0x08, true);
    let symbol = dv.getUint32(0x0C, true);
    let number = dv.getUint32(0x10, true);
    let optSize = dv.getUint16(0x14, true);
    let characteristics = dv.getUint16(0x16, true);
    let optional = optSize != 0 ? PE.readOptionalHeader(inp, offset + 0x18) : null;

    let newOff = 0x18 + optSize + offset;
    let sects = PE.readSectionHeaders(inp, sections, newOff);
    return {
        Characteristics: characteristics,
        Machine: machine,
        Magic: magic,
        OptionalHeaderSize: optSize,
        Sections: sects,
        SymbolCount: number,
        SymbolTableAddress: symbol,
        TimeStamp: timestamp,
        Optional: optional
    }; // 0x18 + (optional == null ? 0 : 0x48 + (optional.Magic == Bitness.BITS64 ? 4*8 : 4*4) + optional.Directories.length * 0x8 + 0x8)
}

namespace Util {
    export function rvaToPhys(pe: PEHeader, rva: number): number {
        let sec: SectionHeader = null;
        for (let section of pe.Sections)
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                sec = section;
        if (sec == null)
            throw "RVA 0x" + rva.toString(16) + " is not in any section?";
        return rva - sec.VirtualAddress + sec.RawDataAddress
    }

    export function physToRva(pe: PEHeader, phys: number): number {
        let sec: SectionHeader = null;
        for (let section of pe.Sections)
            if (phys >= section.RawDataAddress && phys < section.RawDataAddress + section.RawDataSize)
                sec = section;
        if (sec == null)
            throw "PHYS 0x" + phys.toString(16) + " is not in any section?";
        return phys - sec.RawDataSize + sec.VirtualAddress
    }
}
namespace PE {

    export function readOptionalHeader(inp: ArrayBuffer, offset: number): PEOptional {
        let dv = new DataView(inp, offset);
        let magic = dv.getUint16(0x00, true);
        if (magic != 0x010b && magic != 0x020b)
            throw "Invalid optional header magic: " + magic.toString(16)
        let bit: Bitness = magic;
        let majLinker = dv.getUint8(0x02);
        let minLinker = dv.getUint8(0x03);
        let codeSize = dv.getUint32(0x04, true);
        let dataInit = dv.getUint32(0x08, true);
        let dataUnit = dv.getUint32(0x0C, true);
        let entry = dv.getUint32(0x10, true);
        let codeBase = dv.getUint32(0x14, true);
        let dataBase = dv.getUint32(0x18, true);
        let imageBase = dv.getUint32(0x1C, true);
        let sectionAlignment = dv.getUint32(0x20, true);
        let fileAlignment = dv.getUint32(0x24, true);
        let majOperating = dv.getUint16(0x28, true);
        let minOperating = dv.getUint16(0x2A, true);
        let majImage = dv.getUint16(0x2C, true);
        let minImage = dv.getUint16(0x2E, true);
        let majSub = dv.getUint16(0x30, true);
        let minSub = dv.getUint16(0x32, true);
        let win32 = dv.getUint32(0x34, true);
        let imageSize = dv.getUint32(0x38, true);
        let headerSize = dv.getUint32(0x3C, true);
        let checksum = dv.getUint32(0x40, true);
        let subsystem = dv.getUint16(0x44, true)
        let characteristics = dv.getUint16(0x46, true)
        let stackReserve;
        let stackCommit
        let heapReserve;
        let heapCommit;
        if (bit == Bitness.BITS32) {
            stackReserve = dv.getUint32(0x48, true);
            stackCommit = dv.getUint32(0x4C, true);
            heapReserve = dv.getUint32(0x50, true);
            heapCommit = dv.getUint32(0x54, true);
        } else {
            stackReserve = Number(dv.getBigUint64(0x48, true));
            stackCommit = Number(dv.getBigUint64(0x50, true));
            heapReserve = Number(dv.getBigUint64(0x58, true));
            heapCommit = Number(dv.getBigUint64(0x60, true));
        }
        let off = 0x48 + (bit == Bitness.BITS64 ? 4 * 8 : 4 * 4);
        let loaderFlags = dv.getUint32(off, true);
        let rva = dv.getUint32(off + 0x4, true);

        let rvaOff = off + 0x08
        let rvas: DirectoryEntry[] = []
        for (let i = 0; i < rva; i++) {
            let rva = dv.getUint32(rvaOff + (i * 0x08), true)
            let size = dv.getUint32(rvaOff + (i * 0x08) + 2, true)
            let present = true;
            if (rva == 0x00 || size == 0x00)
                present = false;
            rvas[i] = {
                RVA: rva,
                Size: size,
                Present: present
            }
        }
        // @todo update when theres more rvas
        for (let i = rva; i < 0x0f; i++) {
            rva[i] = {
                RVA: 0,
                Size: 0,
                Present: false
            }
        }

        return {
            Characteristics: characteristics,
            Checksum: checksum,
            CodeBase: codeBase,
            CodeSize: codeSize,
            DataBase: dataBase,
            EntryPointAddress: entry,
            FileAlignment: fileAlignment,
            HeaderSize: headerSize,
            HeapCommitSize: heapCommit,
            HeapReserveSize: heapReserve,
            ImageBase: imageBase,
            ImageSize: imageSize,
            InitializedDataSize: dataInit,
            LoaderFlags: loaderFlags,
            Magic: bit,
            MajorImageVersion: majImage,
            MajorLinkerVersion: minLinker,
            MajorOperatingSystemVersion: majOperating,
            MajorSubsystemVersion: minSub,
            MinorImageVersion: minImage,
            MinorLinkerVersion: majLinker,
            MinorOperatingSystemVersion: minOperating,
            MinorSubsystemVersion: minSub,
            Directories: rvas,
            SectionAlignment: sectionAlignment,
            StackCommitSize: stackCommit,
            StackReserveSize: stackReserve,
            Subsystem: subsystem,
            UninitializedDataSize: dataUnit,
            Win32VersionValue: win32
        }
    }

    export function readSectionHeaders(inp: ArrayBuffer, count: number, offset: number): SectionHeader[] {
        let sects: SectionHeader[] = [];
        let dv = new DataView(inp, offset);
        for (let i = 0; i < count; i++) {
            let name = "";
            let off = i * 0x28;
            for (let j = 0; j < 8; j++) {
                let byte = dv.getUint8(off + j);
                if (byte == 0x00)
                    break;
                name += String.fromCharCode(byte)
            }
            let virtSize = dv.getUint32(off + 0x08, true);
            let virtAddr = dv.getUint32(off + 0x0C, true);
            let rawDataSize = dv.getUint32(off + 0x10, true);
            let rawDataAddr = dv.getUint32(off + 0x14, true);
            let relocAddr = dv.getUint32(off + 0x18, true);
            let linesAddr = dv.getUint32(off + 0x1C, true);
            let relocCount = dv.getUint16(off + 0x20, true);
            let lineCount = dv.getUint16(off + 0x22, true);
            let char = dv.getUint32(off + 0x24, true);
            sects.push({
                Characteristics: char,
                LineNumbersAddress: linesAddr,
                LineNumbersCount: lineCount,
                Name: name,
                RawDataAddress: rawDataAddr,
                RawDataSize: rawDataSize,
                RelocationsAddress: relocAddr,
                RelocationsCount: relocCount,
                VirtualAddress: virtAddr,
                VirtualSize: virtSize
            });
        }
        return sects;
    }
}

export function readCor20Header(file: ArrayBuffer, pe: PEHeader): Cor20Header | null {
    if (pe.Optional == null)
        return null;

    let dir = pe.Optional.Directories[DirectoryIndices.NET_METADATA];
    if (!dir.Present)
        return null;
    let offset = Util.rvaToPhys(pe, dir.RVA);
    let dv = new DataView(file, offset);

    let cb = dv.getUint32(0x00, true);
    let majRuntime = dv.getUint16(0x04, true);
    let minRuntime = dv.getUint16(0x06, true);
    let metadataRVA = dv.getUint32(0x08, true);
    let metadataSize = dv.getUint32(0x0C, true);
    let flags = dv.getUint32(0x10, true);
    let entryPointToken = dv.getUint32(0x14, true);
    let resourcesRVA = dv.getUint32(0x18, true);
    let resourcesSize = dv.getUint32(0x1C, true);
    let strongNameSigRVA = dv.getUint32(0x20, true);
    let strongNameSigSize = dv.getUint32(0x24, true);
    let codeManagerTableRVA = dv.getUint32(0x28, true);
    let codeManagerTableSize = dv.getUint32(0x2C, true);
    let vTableFixupsRVA = dv.getUint32(0x30, true);
    let vTableFixupsSize = dv.getUint32(0x34, true);
    let exportAddressTableJumpsRVA = dv.getUint32(0x38, true);
    let exportAddressTableJumpsSize = dv.getUint32(0x3C, true);
    let managedNativeHeaderRVA = dv.getUint32(0x40, true);
    let managedNativeHeaderSize = dv.getUint32(0x44, true);

    return {
        CodeManagerTableRVA: codeManagerTableRVA,
        CodeManagerTableSize: codeManagerTableSize,
        EntrypointToken: entryPointToken,
        ExportAddressTableJumpRVA: exportAddressTableJumpsRVA,
        ExportAddressTableJumpSize: exportAddressTableJumpsSize,
        Flags: flags,
        MajorRuntimeVersion: majRuntime,
        ManagedNativeHeaderSize: managedNativeHeaderSize,
        ManagedNativeHeaderRVA: managedNativeHeaderRVA,
        MetadataRVA: metadataRVA,
        MetadataSize: metadataSize,
        MinorRuntimeVersion: minRuntime,
        ResourcesRVA: resourcesRVA,
        ResourcesSize: resourcesSize,
        Size: cb,
        StrongNameSignatureRVA: strongNameSigRVA,
        StrongNameSignatureSize: strongNameSigSize,
        VTableFixupsRVA: vTableFixupsRVA,
        VTableFixupsSize: vTableFixupsSize
    }
}

export function readMetadataHeader(file: ArrayBuffer, pe: PEHeader, cor: Cor20Header): MetadataHeader {
    let offset = Util.rvaToPhys(pe, cor.MetadataRVA);
    let dv = new DataView(file, offset);

    let signature = dv.getUint32(0x00, true);
    if (signature != 0x424a5342)
        throw "Invalid metadata signature, expected 0x424a5342, got 0x" + signature.toString(16);
    let majVer = dv.getUint16(0x04, true);
    let minVer = dv.getUint16(0x06, true);
    let reserved = dv.getUint32(0x08, true);
    let versionStringLength = dv.getUint32(0x0C, true);
    let str = ""
    for (let i = 0; i < versionStringLength; i++) {
        str += (String.fromCharCode(dv.getUint8(0x10 + i)))
    }
    let flags = dv.getUint16(0x10 + versionStringLength, true);
    let streamCount = dv.getUint16(0x12 + versionStringLength, true);

    let streamOff = 0x14 + versionStringLength;
    let lastOff = 0

    let streams: StreamHeader[] = []
    for (let i = 0; i < streamCount; i++) {
        let realOff = streamOff + lastOff;
        let soffset = dv.getUint32(realOff, true);
        let size = dv.getUint32(realOff + 0x04, true);
        // why microsoft....
        let str = ""
        let nulling = false
        let strsize = 0;
        let remaining = 0;
        for (let j = 0; true; j++) {
            let char = dv.getUint8(realOff + 0x08 + j);
            if (char != 0x00)
                str += String.fromCharCode(char)
            else {
                if (!nulling) {
                    nulling = true;
                    remaining = Math.ceil((str.length+1) / 4) * 4 - str.length;
                    strsize = Math.ceil((str.length+1) / 4) * 4;
                }
                remaining--;
                if(remaining == 0)
                    break
            }
        }
        streams.push({
            Name: str, Offset: soffset + offset, Size: size
        })
        lastOff += 8 + strsize;
    }

    return {
        Flags: flags,
        MajorVersion: majVer,
        MinorVersion: minVer,
        Streams: streams,
        Reserved: reserved,
        Signature: signature,
        VersionString: str.replace("\x00", "")
    }
}
export function readUserStringStream(file: ArrayBuffer, table: StreamHeader): string[] {
    let offset = table.Offset;
    let dv = new DataView(file, offset, table.Size);
    let ret = []
    let idx = 0;
    while(idx < table.Size) {
        let size = dv.getUint8(idx++);
        if((size & 0b11000000) == 0b10000000) {
            size = ((size & 0b00111111) << 8) + dv.getUint8(idx++);
        } else if((size & 0b11100000) == 0b11000000) {
            let x = dv.getUint8(idx++);
            let y = dv.getUint8(idx++);
            let z = dv.getUint8(idx++);
            size = ((size & 0b00011111) << 24) + (x << 16) + (y << 8) + z
        }

        let data = []
        for (let i = 0; i < size; i++) {
            data.push(dv.getUint8(idx++));
        }
        let data2 = []
        for (let i = 0; i < Math.floor(data.length / 2); i++)
            data2.push(data[i*2] + (data[i*2+1] << 8))
        ret.push(String.fromCharCode(...data2))
    }
    return ret;
}
