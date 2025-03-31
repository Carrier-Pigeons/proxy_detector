rule Sec_Ch_Removed
{
    strings:
        $sec_ch = "sec-ch-"
        $sec_ch_normal = "Sec-Ch-"
        $sec_ch_cap = "SEC-CH-"
    condition:
        $sec_ch or
        $sec_ch_normal or
        $sec_ch_cap
}