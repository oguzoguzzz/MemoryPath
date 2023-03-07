class CPatternScan
{
private:
    const CProcess* Process;
    std::unique_ptr<BYTE[]> Data;
    const DWORD* Size;

public:
    CPatternScan() : Process(nullptr), Data(nullptr), Size(nullptr) {}

    CPatternScan(CProcess* Process, char* ModuleName)
        : Process(Process), Size(nullptr)
    {
        if (Process != nullptr && ModuleName != nullptr)
        {
            Size = Process->GetModuleSize(ModuleName);
            Data = std::make_unique<BYTE[]>(*Size);
            auto BytesRead{ SIZE_T() };
            if (!ReadProcessMemory(*Process->GetHandle(), reinterpret_cast<LPCVOID>(Process->GetModuleBaseAddress(ModuleName)), Data.get(), *Size, &BytesRead) || BytesRead != *Size)
            {
                memset(Data.get(), 0, *Size);
            }
        }
    }

    ~CPatternScan()
    {
    }

    auto FindPattern(std::vector<BYTE> Pattern) const -> DWORD
    {
        Pattern.shrink_to_fit();
        for (DWORD i = 0; i < *Size; i++)
        {
            auto DoesMatch{ true };
            for (DWORD j = 0; j < Pattern.size(); j++)
            {
                if (Pattern[j] == 0) continue;
                if (Pattern[j] != Data[i + j]) { DoesMatch = false; break; }
            }
            if (DoesMatch)
                return i;
        }
        return 0;
    }

    auto GetOffset(DWORD Offset) const -> DWORD
    {
        auto Buffer{ DWORD(0) };

        memcpy(&Buffer, &Data[Offset], sizeof(DWORD));

        return Buffer;
    }

    auto GetOffset(std::vector<BYTE> Pattern, DWORD Offset) const -> DWORD
    {
        return GetOffset(FindPattern(Pattern) + Offset);
    }
};
