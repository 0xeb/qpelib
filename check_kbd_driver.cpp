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
* 02/02/2016 - Initial version
*/

#include "qpeutil.hpp"

//--------------------------------------------------------------------------
struct QuickInfo_t
{
    bool bIsKbd;
    bool bNoCode;
    bool bIsKdExtension;
};

//--------------------------------------------------------------------------
static bool GetQuickInfo(
    LPCTSTR PEFile, 
    QuickInfo_t &qi)
{
    qpeutil_t util;
    if (!util.open(PEFile))
        return false;

    class qinfo_visitor_t : public qpeutil_t::exports_visitor_t,
                            public qpeutil_t::sections_visitor_t
    {
    private:
        int n_kbd_exports;
        int n_code_sections;
        bool b_is_kd_extension;

        bool name(DWORD ordinal, DWORD eat_rva, const char* name) override 
        { 
            if (strcmp(name, "KbdLayerDescriptor") == 0)
                n_kbd_exports++;
            if (strcmp(name, "KbdNlsLayerDescriptor") == 0)
                n_kbd_exports++;

            if (strcmp(name, "KdInitializeLibrary") == 0)
                b_is_kd_extension = true;

            return true;
        }

        bool ord(DWORD ordinal, DWORD eat_rva) override 
        { 
            return true; 
        }

        virtual bool section(const IMAGE_SECTION_HEADER *section) override
        {
            if ((section->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
                ++n_code_sections;

            return n_code_sections > 0 ? false : true;
        }

    public:
        qinfo_visitor_t() : n_kbd_exports(0), n_code_sections(0), b_is_kd_extension(false)
        {
        }

        bool operator ()(qpeutil_t &util)
        {
            util.visit_sections(this);
            return util.visit_exports(this);
        }

        const bool is_keyboard_dll() const { return n_kbd_exports != 0; }
        const bool is_kd_extension_dll() const { return b_is_kd_extension; }
        const bool has_code_sections() const { return n_code_sections > 0; }

    };

    qinfo_visitor_t v;
    if (v(util))
    {
        qi.bIsKbd = v.is_keyboard_dll();
        qi.bNoCode = !v.has_code_sections();
        qi.bIsKdExtension = v.is_kd_extension_dll();
        return true;
    }
    else
    {
        return false;
    }
}

//--------------------------------------------------------------------------
static bool DumpAsXml(
    LPCTSTR OutXml, 
    QuickInfo_t &qi)
{
    FILE *fp_out;
    if (_tfopen_s(&fp_out, OutXml, _TEXT("w")) != 0)
        return false;

    _ftprintf(
        fp_out,
        _TEXT("<QuickInfo>\n")
            _TEXT("\t<KeyboardDriver>%d</KeyboardDriver>\n")
            _TEXT("\t<HasCode>%d</HasCode>\n")
           _TEXT("\t<IsKdExtension>%d</IsKdExtension>\n")
        _TEXT("</QuickInfo>\n"),
        qi.bIsKbd ? 1 : 0,
        qi.bNoCode ? 0 : 1,
        qi.bIsKdExtension ? 1 : 0);

    fclose(fp_out);

    return true;
}

//--------------------------------------------------------------------------
static bool DumpAsCSV(
    LPCTSTR OutCsv, 
    QuickInfo_t &qi)
{
    FILE *fp_out;
    if (_tfopen_s(&fp_out, OutCsv, _TEXT("w")) != 0)
        return false;

    _ftprintf(
        fp_out,
        _TEXT("KeyboardDriver,%d\n")
        _TEXT("HasCode,%d\n")
        _TEXT("IsKdExtension,%d\n"),
        qi.bIsKbd ? 1 : 0,
        qi.bNoCode ? 0 : 1,
        qi.bIsKdExtension ? 1 : 0);

    fclose(fp_out);

    return true;
}

//--------------------------------------------------------------------------
int _tmain(int argc, TCHAR *argv[])
{
    if (argc < 3)
    {
        printf(
            "QuickInfo v0.1 (" __DATE__ " " __TIME__ ")\n"
            "-------------------------------------\n"
            "\n"
            "Usage:\n"
            "    QuickInfo InputPEFile OutputResultFile [ResultType: 0=XML, 1=CSV]\n"
            "\n"
        );
        return -1;
    }

    bool bOk = false;
    __try
    {
        QuickInfo_t qi;

        if (!GetQuickInfo(argv[1], qi))
        {
            _tprintf(
                _TEXT("Failed to get PE info for file '%s'\n"), 
                argv[1]);

            return -1;
        }

        int out_type = (argc > 3) ? _ttoi(argv[3]) : 0;

        if (out_type == 1)
            bOk = DumpAsCSV(argv[2], qi);
        else
            bOk = DumpAsXml(argv[2], qi);

        if (!bOk)
        {
            _tprintf(
                _TEXT("Failed to create output file '%s' of type(%d).\n"),
                argv[2], 
                out_type);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        _tprintf(
            _TEXT("Exception occurred while processing '%s'."),
            argv[1]);

        return -2;
    }

    return bOk ? 0 : -3;
}