rule Sec_Ch_Ua_Headers_Capitalization_Change
{
    strings:
        $sec_ch_ua_old = "sec-ch-ua" nocase
        $sec_ch_ua_new = "Sec-Ch-Ua"
        $sec_ch_ua_mobile_old = "sec-ch-ua-mobile" nocase
        $sec_ch_ua_mobile_new = "Sec-Ch-Ua-Mobile"
        $sec_ch_ua_platform_old = "sec-ch-ua-platform" nocase
        $sec_ch_ua_platform_new = "Sec-Ch-Ua-Platform"
    condition:
        ($sec_ch_ua_old and $sec_ch_ua_new) or
        ($sec_ch_ua_mobile_old and $sec_ch_ua_mobile_new) or
        ($sec_ch_ua_platform_old and $sec_ch_ua_platform_new)
}