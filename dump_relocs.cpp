/* ----------------------------------------------------------------------------- 
* QuickPEInfo - Copyright (c) Elias Bachaalany <lallousz-x86@yahoo.com>
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
* ----------------------------------------------------------------------------- 
*
*/

#include "qpeutil.hpp"

const char *reloctype_to_str(int reloctype) 
{
    switch (reloctype) 
    {
        case 0: return "IMAGE_REL_BASED_ABSOLUTE";
        case 1: return "IMAGE_REL_BASED_HIGH";
        case 2: return "IMAGE_REL_BASED_LOW";
        case 3: return "IMAGE_REL_BASED_HIGHLOW";
        case 4: return "IMAGE_REL_BASED_HIGHADJ";
        case 5: return "IMAGE_REL_BASED_MACHINE_SPECIFIC_5";
        case 6: return "IMAGE_REL_BASED_RESERVED";
        case 7: return "IMAGE_REL_BASED_MACHINE_SPECIFIC_7";
        case 8: return "IMAGE_REL_BASED_MACHINE_SPECIFIC_8";
        case 9: return "IMAGE_REL_BASED_MACHINE_SPECIFIC_9";
        case 10: return "IMAGE_REL_BASED_DIR64";
        default: return "UNKNOWN_RELOC_TYPE";
    }
}

//--------------------------------------------------------------------------
int _tmain(int argc, TCHAR *argv[])
{
    //if (argc < 2)
    //{
    //    printf(
    //        "QuickInfo v0.1 (" __DATE__ " " __TIME__ ")\n"
    //        "-------------------------------------\n"
    //        "\n"
    //        "Usage:\n"
    //        "    QuickInfo InputPEFile\n"
    //        "\n"
    //    );
    //    return -1;
    //}

    class dump_relocs : public qpeutil_t::reloc_visitor_t
    {
        virtual bool entry(const DWORD entry_rva, const WORD type, const WORD offset, DWORD reloc_rva) {
            printf("Reloc @ %I64X: entry: %08X type:%s (%04X) offset: %04X rva: %08X\n", 
                reloc_rva + pe->image_base(),
                entry_rva, 
                reloctype_to_str(type), type,
                offset, reloc_rva);
            return true; 
        }
    };

    dump_relocs dr;
    qpeutil_t util;
    if (!util.open(R"(c:\windows\explorer.exe)"))
        return 1;

    util.visit_relocs(&dr);

    return 0;
}