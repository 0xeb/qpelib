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

//--------------------------------------------------------------------------
class peutil_t
{
protected:
    FILE *m_fp;
    IMAGE_SECTION_HEADER *m_sections;
    IMAGE_DOS_HEADER m_idh;
    union
    {
        IMAGE_NT_HEADERS32 m_inh32;
        IMAGE_NT_HEADERS64 m_inh64;
    };
    bool m_bIs64;

    long m_fsize;
    long m_sections_pos;

    bool read_asciisz(
        size_t rva, 
        char *buf, 
        size_t buf_sz)
    {
        size_t phys;
        if (!rva2phys(rva, &phys))
            return false;

        long pos = long(phys);
        if (pos >= m_fsize)
            return false;

        if (fseek(m_fp, pos, SEEK_SET) != 0)
            return false;

        long max_pos = min(pos + (long)buf_sz, m_fsize);
        long max_sz = max_pos - pos;

        return fread(buf, 1, max_sz, m_fp) == max_sz;
    }

public:
    class exported_name_visitor_t
    {
    public:
        virtual bool begin(IMAGE_DATA_DIRECTORY *dir) = 0;
        virtual bool export_name(const char *name) = 0;
    };

    class sections_visitor_t
    {
    public:
        virtual bool section(const IMAGE_SECTION_HEADER *section) = 0;
    };

    peutil_t(): m_sections(nullptr), m_fp(nullptr), m_fsize(0), m_sections_pos(0)
    {
    }

    ~peutil_t()
    {
        close();
    }

    void close()
    {
        if (m_sections != nullptr)
        {
            delete[] m_sections;
            m_sections = nullptr;
        }

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
            m_sections = new IMAGE_SECTION_HEADER[nb_sections];
            if (m_sections == nullptr)
                break;

            // Go to sections
            m_sections_pos = m_idh.e_lfanew + (m_bIs64 ? sizeof(m_inh64) : sizeof(m_inh32));
            if (fseek(m_fp, m_sections_pos, SEEK_SET) != 0)
                break;

            // Read all sections
            if (fread(m_sections, sizeof(IMAGE_SECTION_HEADER), nb_sections, m_fp) != nb_sections)
                break;

            bOk = true;
        } while (false);

        if (!bOk)
            close();

        return bOk;
    }

    bool read_buf_rva(
        size_t rva, 
        void *buf, 
        size_t buf_sz)
    {
        size_t phys;
        if (!rva2phys(rva, &phys))
            return false;
        else
            return read_buf_phys(phys, buf, buf_sz);
    }

    bool read_buf_phys(
        size_t phys,
        void *buf,
        size_t buf_sz)
    {
        if (fseek(m_fp, (long)phys, SEEK_SET) != 0)
            return false;
        else
            return fread(buf, buf_sz, 1, m_fp) == 1;
    }

    bool visit_exported_names(exported_name_visitor_t *v)
    {
        auto exp_idd = m_bIs64 ?   m_inh64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                 : m_inh32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        // No export directory
        if (!v->begin(&exp_idd) || exp_idd.VirtualAddress == 0)
            return true;

        // Read the image export directory
        IMAGE_EXPORT_DIRECTORY ied;
        if (!read_buf_rva(exp_idd.VirtualAddress, &ied, sizeof(ied)))
            return false;

        // If there is an IED but no names then fail gracefully
        if (ied.NumberOfNames == 0)
            return true;

        // Read the names RVA
        PDWORD names_rvas = new DWORD[ied.NumberOfNames];
        if (names_rvas == nullptr)
            return false;

        bool bOk = false;

        char name[MAX_PATH + 1] = { 0 };
        do
        {
            if (!read_buf_rva(ied.AddressOfNames, names_rvas, sizeof(DWORD) * ied.NumberOfNames))
                break;

            bool bReadErr = false;
            for (DWORD c = ied.NumberOfNames, i = 0; i < c; i++)
            {
                if (!read_asciisz(names_rvas[i], name, MAX_PATH - 1))
                {
                    bReadErr = true;
                    break;
                }
                name[MAX_PATH] = '\0';
                if (v != nullptr && !v->export_name(name))
                    break;
            }
            bOk = !bReadErr;
        } while (false);

        delete[] names_rvas;

        return bOk;
    }

    DWORD64 image_base()
    {
        return m_bIs64 ? m_inh64.OptionalHeader.ImageBase : m_inh32.OptionalHeader.ImageBase;
    }

    void visit_sections(sections_visitor_t *visitor)
    {
        for (size_t i = 0, c = get_nb_sections(); i < c; i++)
        {
            if (visitor != nullptr && !visitor->section(&m_sections[i]))
                break;
        }
    }

    const inline size_t get_nb_sections() const
    {
        return size_t(m_inh32.FileHeader.NumberOfSections);
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