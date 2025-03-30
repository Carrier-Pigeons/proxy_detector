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
        (not $sec_ch_ua_old or $sec_ch_ua_new) and
        (not $sec_ch_ua_mobile_old or $sec_ch_ua_mobile_new) and
        (not $sec_ch_ua_platform_old or $sec_ch_ua_platform_new)
}