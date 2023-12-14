import pefile , argparse , os , sys 

from core.prompt import RavePrompt as prompt , Colors

ORANGE = Colors.ORANGE

END = Colors.END

RED = Colors.RED



MZ_SIG = '0x5a4d'

parser = argparse.ArgumentParser (

    prog = 'PE Inspector',

    description = 'Simple python tool to parse windows PE files.'

)


parser.add_argument('-f' , '--file' , help = 'Path to file to be parsed.')

parser.add_argument('--importsearch' , help = 'Search a function up in the parsed import table directory.')
parser.add_argument('--exportsearch' , help = 'Search a function up in the parsed export table directory.')



arguments = parser.parse_args()


file_path = arguments.file

exp_search = arguments.exportsearch
imp_search = arguments.importsearch



if not os.path.isfile(file_path):

    prompt.print_min('File does not exist!')

    sys.exit(0)




prompt.print_plus('Parsing file ...')


file = pefile.PE(file_path)


prompt.print_plus(f'Parsed! , All RVAs / Values are in {ORANGE}HEX{END}.')







DOS_HEADER = file.DOS_HEADER
NT_HEADERS = file.NT_HEADERS
OPTIONAL_HEADER = file.OPTIONAL_HEADER
FILE_HEADER = file.FILE_HEADER


if imp_search:

    import_search = imp_search.lower()

    if hasattr(file , 'DIRECTORY_ENTRY_IMPORT'):
        for entry in file.DIRECTORY_ENTRY_IMPORT:

            dll_name = entry.dll.decode('utf8')

            for imp in entry.imports:

                if not imp.name:
                    continue
                

                name = imp.name.decode()
                if import_search in name.lower() or import_search == name.lower():

                    prompt.print_imp(f'Found function {ORANGE}{name}{END} in {ORANGE}{dll_name.lower()}{END}')

                    prompt.vert (
                        imp.name.decode(),

                        DLL=dll_name.lower(),

                        Address = hex(imp.address)

                    )


            sys.exit(0)
                
    else:

        prompt.print_min('File does not have an IAT.')

        sys.exit(0)


if exp_search:


    if hasattr(file , 'DIRECTORY_ENTRY_EXPORT'):

        for exp in file.DIRECTORY_ENTRY_EXPORT.symbols:


            if exp.name is not None:

                if prompt.is_int_from_str(exp_search):

                    # ordinal search
                    against = int (exp_search)
                    ordinal = exp.ordinal


                    name = exp.name.decode()

                    if against == ordinal:

                        prompt.print_imp(f'Found function {ORANGE}{name}{END} in EAT')

                        prompt.vert( 

                        name,

                        Address = hex(file.OPTIONAL_HEADER.ImageBase + exp.address),

                        Ordinal = exp.ordinal

                    )
                else:

                    name = exp.name.decode()

                    

                    if exp_search.lower() in name.lower() or name.lower() == exp_search.lower():
                        prompt.print_imp(f'Found function {ORANGE}{name}{END} in EAT')
                        prompt.vert( 

                        name,

                        Address = hex(file.OPTIONAL_HEADER.ImageBase + exp.address),

                        Ordinal = exp.ordinal

                    )

        sys.exit(0)
       


    else:

        prompt.print_min('File does not have an EAT.')








################# HEADERS #################

# DOS HEADER STUFF #

e_magic = hex(DOS_HEADER.e_magic)
e_cblp = hex(DOS_HEADER.e_cblp)
e_cp = hex(DOS_HEADER.e_cp)
e_crlc = hex(DOS_HEADER.e_crlc)
e_cparhdr = hex(DOS_HEADER.e_cparhdr)
e_minalloc = hex(DOS_HEADER.e_minalloc)
e_maxalloc = hex(DOS_HEADER.e_maxalloc)
e_ss = hex(DOS_HEADER.e_ss)
e_sp = hex(DOS_HEADER.e_sp)
e_csum = hex(DOS_HEADER.e_csum)
e_ip = hex(DOS_HEADER.e_ip)
e_cs = hex(DOS_HEADER.e_cs)
e_lfarlc = hex(DOS_HEADER.e_lfarlc)
e_ovno = hex(DOS_HEADER.e_ovno)
e_oemid = hex(DOS_HEADER.e_oemid)
e_oeminfo = hex(DOS_HEADER.e_oeminfo)
e_lfanew = hex(DOS_HEADER.e_lfanew)

# NT HEADER STUFF #

Signature = hex(NT_HEADERS.Signature)

if e_magic != MZ_SIG:

    prompt.print_min('File appears to be invalid ...')

    sys.exit(0)

# FILE HEADER STUFF #

Machine = hex(FILE_HEADER.Machine)
NumberOfSections = hex(FILE_HEADER.NumberOfSections)
TimeDateStamp = hex(FILE_HEADER.TimeDateStamp)
PointerToSymbolTable = hex(FILE_HEADER.PointerToSymbolTable)
NumberOfSymbols = hex(FILE_HEADER.NumberOfSymbols)
SizeOfOptionalHeader = hex(FILE_HEADER.SizeOfOptionalHeader)
Characteristics = hex(FILE_HEADER.Characteristics)
prompt.print_seperator()
prompt.vert(
    text='DOS HEADER',
    e_magic=e_magic,
    e_cblp=e_cblp,
    e_cp=e_cp,
    e_crlc=e_crlc,
    e_cparhdr=e_cparhdr,
    e_minalloc = e_minalloc,
    e_maxalloc = e_maxalloc,
    e_ss = e_ss,
    e_sp=e_sp,
    e_csum=e_csum,
    e_ip=e_ip,
    e_cs=e_cs,
    e_lfarlc=e_lfarlc,
    e_ovno=e_ovno,
    e_oemid=e_oemid,
    e_oeminfo=e_oeminfo,
    e_lfanew=e_lfanew

)
prompt.print_seperator()

prompt.vert('NT HEADERS', Signature=Signature)

prompt.print_seperator()

prompt.vert(

    'FILE HEADER',

    Machine=Machine,
    NumberOfSections=NumberOfSections,
    TimeDateStamp=TimeDateStamp,
    PointerToSymbolTable=PointerToSymbolTable,
    NumberOfSymbols=NumberOfSymbols,
    SizeOfOptionalHeader=SizeOfOptionalHeader,
    Characteristics=Characteristics,

)

prompt.print_seperator()

optional_header = file.OPTIONAL_HEADER


Magic = hex(optional_header.Magic)
MajorLinkerVersion = hex(optional_header.MajorLinkerVersion)
MinorLinkerVersion = hex(optional_header.MinorLinkerVersion)
SizeOfCode = hex(optional_header.SizeOfCode)
SizeOfInitializedData = hex(optional_header.SizeOfInitializedData)
SizeOfUninitializedData = hex(optional_header.SizeOfUninitializedData)
AddressOfEntryPoint = hex(optional_header.AddressOfEntryPoint)
BaseOfCode = hex(optional_header.BaseOfCode)
ImageBase = hex(optional_header.ImageBase)
SectionAlignment = hex(optional_header.SectionAlignment)
FileAlignment = hex(optional_header.FileAlignment)
MajorOperatingSystemVersion = hex(optional_header.MajorOperatingSystemVersion)
MinorOperatingSystemVersion = hex(optional_header.MinorOperatingSystemVersion)
MajorImageVersion = hex(optional_header.MajorImageVersion)
MinorImageVersion = hex(optional_header.MinorImageVersion)
MajorSubsystemVersion = hex(optional_header.MajorSubsystemVersion)
MinorSubsystemVersion = hex(optional_header.MinorSubsystemVersion)
Reserved1 = hex(optional_header.Reserved1)
SizeOfImage = hex(optional_header.SizeOfImage)
SizeOfHeaders = hex(optional_header.SizeOfHeaders)
CheckSum = hex(optional_header.CheckSum)
Subsystem = hex(optional_header.Subsystem)
DllCharacteristics = hex(optional_header.DllCharacteristics)
SizeOfStackReserve = hex(optional_header.SizeOfStackReserve)
SizeOfStackCommit = hex(optional_header.SizeOfStackCommit)
SizeOfHeapReserve = hex(optional_header.SizeOfHeapReserve)
SizeOfHeapCommit = hex(optional_header.SizeOfHeapCommit)
LoaderFlags = hex(optional_header.LoaderFlags)
NumberOfRvaAndSizes = hex(optional_header.NumberOfRvaAndSizes)


prompt.vert(
        'OPTIONAL HEADER',
        Magic=Magic,
        MajorLinkerVersion=MajorLinkerVersion,
        MinorLinkerVersion=MinorLinkerVersion,
        SizeOfCode=SizeOfCode,
        SizeOfInitializedData=SizeOfInitializedData,
        SizeOfUninitializedData=SizeOfUninitializedData,
        AddressOfEntryPoint=AddressOfEntryPoint,
        BaseOfCode=BaseOfCode,
        ImageBase=ImageBase,
        SectionAlignment=SectionAlignment,
        FileAlignment=FileAlignment,
        MajorOperatingSystemVersion=MajorOperatingSystemVersion,
        MinorOperatingSystemVersion=MinorOperatingSystemVersion,
        MajorImageVersion=MajorImageVersion,
        MinorImageVersion=MinorImageVersion,
        MajorSubsystemVersion=MajorSubsystemVersion,
        MinorSubsystemVersion=MinorSubsystemVersion,
        Reserved1=Reserved1,
        SizeOfImage=SizeOfImage,
        SizeOfHeaders=SizeOfHeaders,
        CheckSum=CheckSum,
        Subsystem=Subsystem,
        DllCharacteristics=DllCharacteristics,
        SizeOfStackReserve=SizeOfStackReserve,
        SizeOfStackCommit=SizeOfStackCommit,
        SizeOfHeapReserve=SizeOfHeapReserve,
        SizeOfHeapCommit=SizeOfHeapCommit,
        LoaderFlags=LoaderFlags,
        NumberOfRvaAndSizes=NumberOfRvaAndSizes,
    )


prompt.print_imp('Parsing Sections ...')
prompt.print_seperator()

################# SECTIONS #################




for section in file.sections:

    name = section.Name.decode()
    address = hex(section.VirtualAddress)
    size = hex(section.SizeOfRawData)

    prompt.vert(
        f'\'{name}\' Section',
        Name=name,
        SizeOfRawData=size,
        VirtualAddress=address,

    )
    prompt.print_seperator()

################# DIRECTORIES #################



## IAT ##

if hasattr(file , 'DIRECTORY_ENTRY_IMPORT'):
    for entry in file.DIRECTORY_ENTRY_IMPORT:

        dll = entry.dll.decode('utf8')

        for imp in entry.imports:

            if imp.name is not None:
                prompt.vert(
                    dll,

                    Name=imp.name.decode(),
                    Address= hex(imp.address)


                )


        prompt.print_seperator()

## EAT ##


if hasattr(file , 'DIRECTORY_ENTRY_EXPORT'):

    for exp in file.DIRECTORY_ENTRY_EXPORT.symbols:


        if exp.name is not None:

            prompt.vert( 

                exp.name.decode(),

                Address = hex(file.OPTIONAL_HEADER.ImageBase + exp.address),

                Ordinal = exp.ordinal

            )



    prompt.print_seperator()
