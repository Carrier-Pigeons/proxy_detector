rule Sec_Ch_Removed
{
    strings:
        $sec_ch = "sec-ch-" nocase
    condition:
        not $sec_ch
}