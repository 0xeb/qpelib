#pragma once

/* -----------------------------------------------------------------------------
* QuickPEInfo - Copyright (c) Elias Bachaalany <elias.bachaalany@gmail.com>
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
*/

#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <map>
#include <vector>

//--------------------------------------------------------------------------
class peutil_t
{
protected:
    FILE *m_fp = nullptr;
    std::vector<IMAGE_SECTION_HEADER> m_sections;
    IMAGE_DOS_HEADER m_idh;
    union
    {
        IMAGE_NT_HEADERS64 m_inh64;
        IMAGE_NT_HEADERS32 m_inh32;
    };
    bool m_bIs64 = false;

    long m_fsize = 0;
    long m_sections_pos = 0;

public:
    class exports_visitor_t
    {
    public:
        peutil_t* pe = nullptr;
        virtual bool dir(const IMAGE_EXPORT_DIRECTORY* dir) { return true; }
        virtual bool fwd_name(DWORD ordinal, const char* name, const char *fwd) { return true; }
        virtual bool name(DWORD ordinal, DWORD eat_rva, const char* name) { return true; }
        virtual bool ord(DWORD ordinal, DWORD eat_rva) { return true; }
    };

    class imports_visitor_t
    {
    public:
        peutil_t* pe = nullptr;
        virtual bool desc(const IMAGE_IMPORT_DESCRIPTOR* dir, const char *dllname) { return true; }
        virtual bool name(const char* dll, const char* name, WORD hint, DWORD ibn_rva = 0) { return true; }
        virtual bool ord(const char* dll, uint16_t ordinal, DWORD thunk_rva = 0) { return true; }
    };

    class sections_visitor_t
    {
    public:
        virtual bool section(const IMAGE_SECTION_HEADER *section) = 0;
    };

    ~peutil_t()
    {
        close();
    }

    const bool is_peplus() const
    {
        return m_bIs64;
    }
    
    bool read_asciisz(
        size_t rva,
        char *buf,
        size_t buf_sz,
        size_t *str_len = nullptr)
    {
        if (str_len)
            *str_len = 0;
        
        size_t phys;
        if (!rva2phys(rva, &phys))
            return false;

        if (fseek(m_fp, (long)phys, SEEK_SET) != 0)
            return false;
        
        while (buf_sz != 0)
        {
            if (fread(buf, 1, 1, m_fp) == 0)
                break;
            buf_sz -= 1;
            if (str_len)
                *str_len += 1;
            
            if (*buf++ == '\0')
                return true;
        }
        return false;
    }

    void close()
    {
        m_sections.clear();

        if (m_fp != nullptr)
        {
            fclose(m_fp);
            m_fp = nullptr;
        }
    }

    bool open(LPCTSTR File)
    {
        // Close previous file
        close();

        // Open input file again
        if (_tfopen_s(&m_fp, File, _TEXT("rb")) != 0)
            return false;

        bool bOk = false;
        do 
        {
            fseek(m_fp, 0, SEEK_END);
            m_fsize = ftell(m_fp);

            fseek(m_fp, 0, SEEK_SET);

            // Read DOS header
            if (fread(&m_idh, sizeof(m_idh), 1, m_fp) != 1)
                break;

            // Check signature
            if (m_idh.e_magic != IMAGE_DOS_SIGNATURE)
                break;

            // Goto NT headers
            if (fseek(m_fp, m_idh.e_lfanew, SEEK_SET) != 0)
                break;

            // Read NT headers 32 (in all cases)
            if (fread(&m_inh32, sizeof(m_inh32), 1, m_fp) != 1)
                break;

            // Verify signature
            if (m_inh32.Signature != IMAGE_NT_SIGNATURE)
                break;

            // Determine the PE file's bitness
            m_bIs64 = m_inh32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            if (m_bIs64)
            {
                // Go back and read the 64bit version of the optional header
                if (fseek(m_fp, m_idh.e_lfanew, SEEK_SET) != 0)
                    break;

                if (fread(&m_inh64, sizeof(m_inh64), 1, m_fp) != 1)
                    break;
            }

            // Get the number of sections
            auto nb_sections = get_nb_sections();

            // Allocate section storage
            m_sections.resize(nb_sections);

            // Go to sections
            m_sections_pos = m_idh.e_lfanew + (m_bIs64 ? sizeof(m_inh64) : sizeof(m_inh32));
            if (fseek(m_fp, m_sections_pos, SEEK_SET) != 0)
                break;

            // Read all sections
            if (fread(&m_sections[0], sizeof(IMAGE_SECTION_HEADER), nb_sections, m_fp) != nb_sections)
                break;

            bOk = true;
        } while (false);

        if (!bOk)
            close();

        return bOk;
    }

    bool read_buf_rva(
        const size_t rva, 
        void *buf, 
        const size_t buf_sz)
    {
        size_t phys;
        if (!rva2phys(rva, &phys))
            return false;
        else
            return read_buf_phys(phys, buf, buf_sz);
    }

    bool read_buf_phys(
        const size_t phys,
        void *buf,
        const size_t buf_sz)
    {
        if (fseek(m_fp, (long)phys, SEEK_SET) != 0)
            return false;
        else
            return fread(buf, buf_sz, 1, m_fp) == 1;
    }

    inline const IMAGE_DATA_DIRECTORY *get_idd(size_t idd_idx) const
    {
        if (idd_idx >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
            return nullptr;

        return m_bIs64 ? &m_inh64.OptionalHeader.DataDirectory[idd_idx]
                       : &m_inh32.OptionalHeader.DataDirectory[idd_idx];
    }

    inline const IMAGE_DATA_DIRECTORY *iat_idd() const
    {
        return get_idd(IMAGE_DIRECTORY_ENTRY_IAT);
    }

    inline const IMAGE_DATA_DIRECTORY *exp_idd() const
    {
        return get_idd(IMAGE_DIRECTORY_ENTRY_EXPORT);
    }

    inline const IMAGE_DATA_DIRECTORY *imp_idd() const
    {
        return get_idd(IMAGE_DIRECTORY_ENTRY_IMPORT);
    }

    bool visit_exports(exports_visitor_t *v)
    {
        if (v != nullptr)
            v->pe = this;

        const auto exp_idd = this->exp_idd();

        DWORD exp_rva = exp_idd->VirtualAddress;
        DWORD exp_end_rva = exp_rva + exp_idd->Size;

        // No export directory
        if (exp_rva == 0)
            return true;

        // Read the image export directory
        IMAGE_EXPORT_DIRECTORY ied;
        if (!read_buf_rva(exp_idd->VirtualAddress, &ied, sizeof(ied)))
            return false;

        // If there is an IED but no names then fail gracefully
        if (ied.NumberOfNames == 0 || (v != nullptr && !v->dir(&ied)))
            return true;

        bool bOk = false;
        char name[1024 + 1] = { 0 };
        char fwd_name[1024 + 1] = { 0 };
        do
        {
            std::vector<DWORD> names_rvas;
            std::map<DWORD, DWORD> name_ordinals_map;
            if (ied.NumberOfNames > 0)
            {
                // Read the whole names array
                names_rvas.resize(ied.NumberOfNames);
                if (!read_buf_rva(ied.AddressOfNames, &names_rvas[0], sizeof(DWORD) * names_rvas.size()))
                    break;

                // Read the names ordinals array and create the mapping
                std::vector<WORD> name_ordinals;
                name_ordinals.resize(ied.NumberOfNames);
                if (!read_buf_rva(ied.AddressOfNameOrdinals, &name_ordinals[0], sizeof(WORD) * name_ordinals.size()))
                    break;

                for (size_t i = 0; i < name_ordinals.size(); i++)
                    name_ordinals_map[name_ordinals[i]] = DWORD(i);
            }

            bool bReadErr = false;
            for (DWORD i=0, c = ied.NumberOfFunctions; i < c; i++)
            {
                DWORD func_rva;
                if (!read_buf_rva(ied.AddressOfFunctions + (i * sizeof(DWORD)), &func_rva, sizeof(DWORD)))
                {
                    bReadErr = true;
                    break;
                }
                // Unused
                if (func_rva == 0)
                    continue;

                DWORD ordinal = i + ied.Base;

                // Pure ordinal?
                auto p = name_ordinals_map.find(i);
                if (p == name_ordinals_map.end())
                {
                    if (v && !v->ord(ordinal, func_rva))
                        return true;
                }
                else
                {
                    if (!read_asciisz(names_rvas[p->second], name, sizeof(name) - 2))
                    {
                        bReadErr = true;
                        break;
                    }
                    name[sizeof(name) - 1] = '\0';

                    // Forwarded name?
                    if (func_rva >= exp_rva && func_rva <= exp_end_rva)
                    {
                        if (!read_asciisz(func_rva, fwd_name, sizeof(fwd_name) - 2))
                        {
                            bReadErr = true;
                            break;
                        }
                        fwd_name[sizeof(fwd_name) - 1] = '\0';
                        if (v != nullptr && !v->fwd_name(ordinal, name, fwd_name))
                            return true;
                    }
                    // Named import
                    else
                    {
                        if (v != nullptr && !v->name(ordinal, func_rva, name))
                            return true;
                    }
                }
            }
            bOk = !bReadErr;
        } while (false);

        return bOk;
    }

    bool visit_imports(imports_visitor_t *v)
    {
        if (v != nullptr)
            v->pe = this;

        const auto imp_idd = this->imp_idd();

        DWORD64 ord_mask = m_bIs64 ? 1ull << 63 : 1u << 31;

        // No import directory
        if (imp_idd->VirtualAddress == 0)
            return true;
        
        char dllname[1024];
        char api_name[1024*2];

        for (DWORD iid_rva = imp_idd->VirtualAddress;; iid_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            // Read the image import descriptor
            IMAGE_IMPORT_DESCRIPTOR iid;
            if (!read_buf_rva(iid_rva, &iid, sizeof(iid)))
                return false;

            if (iid.Name == 0)
                break;

            // Read DLL name
            if (!read_asciisz(iid.Name, dllname, sizeof(dllname) - 1))
                return false;

            if (v != nullptr && !v->desc(&iid, dllname))
                return true;

            // Let's walk the OriginalFirstThunk table
            DWORD thunk_data_size = m_bIs64 ? sizeof(DWORD64) : sizeof(DWORD);
            for (DWORD thunk_rva = iid.FirstThunk;; thunk_rva += thunk_data_size)
            {
                DWORD64 thunk_data = 0;
                if (!read_buf_rva(thunk_rva, &thunk_data, thunk_data_size))
                    return false;

                // End
                if (thunk_data == 0)
                    break;

                if (thunk_data & ord_mask)
                {
                    if (v != nullptr && !v->ord(dllname, uint16_t(thunk_data & ~ord_mask), thunk_rva))
                        return true;
                }
                else
                {
                    // Read the import by name
                    DWORD ibn_rva = DWORD(thunk_data); //_IMAGE_IMPORT_BY_NAME rva;

                    WORD hint;
                    if (!read_buf_rva(ibn_rva, &hint, sizeof(hint)))
                        return false;

                    if (!read_asciisz(ibn_rva + sizeof(hint), api_name, sizeof(api_name) - 1))
                        return false;

                    if (v != nullptr && !v->name(dllname, api_name, hint, ibn_rva))
                        return true;
                }
            }
        }

        return true;
    }

    const DWORD64 image_base() const {
        return m_bIs64 ? m_inh64.OptionalHeader.ImageBase : m_inh32.OptionalHeader.ImageBase;
    }

    void visit_sections(sections_visitor_t *visitor)
    {
        if (visitor == nullptr)
            return;

        for (size_t i = 0, c = get_nb_sections(); i < c; i++)
        {
            if (!visitor->section(&m_sections[i]))
                break;
        }
    }

    const inline size_t get_nb_sections() const {
        return size_t(m_inh32.FileHeader.NumberOfSections);
    }

    const IMAGE_SECTION_HEADER *get_sections() const {
        return &m_sections[0];
    }

    bool rva2phys(size_t rva, size_t *phys)
    {
        for (size_t i = 0, c = get_nb_sections(); i < c; i++)
        {
            auto &sec = m_sections[i];
            if ((rva >= sec.VirtualAddress) && (rva < sec.VirtualAddress + sec.Misc.VirtualSize))
            {
                if (phys != nullptr)
                    *phys = sec.PointerToRawData + (rva - sec.VirtualAddress);
                return true;
            }
        }
        return false;
    }

    bool phys2rva(size_t phys, size_t *rva)
    {
        for (size_t i = 0, c = get_nb_sections(); i < c; i++)
        {
            auto &sec = m_sections[i];
            if ((phys >= sec.PointerToRawData) && (phys < sec.PointerToRawData + sec.SizeOfRawData))
            {
                if (rva != nullptr)
                    *rva = sec.VirtualAddress + (phys - sec.PointerToRawData);
                return true;
            }
        }
        return false;
    }
};
