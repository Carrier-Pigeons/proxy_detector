rule Sec_Ch_Ua_Headers_Capitalization_Change
{
    strings:
        $sec_ch_ua_old = "sec-ch-ua" nocase
        $sec_ch_ua_new = "Sec-Ch-Ua"
        $sec_ch_ua_mobile_old = "sec-ch-ua-mobile" nocase
        $sec_ch_ua_mobile_new = "Sec-Ch-Ua-Mobile"
        $sec_ch_ua_platform_old = "sec-ch-ua-platform" nocase
        $sec_ch_ua_platform_new = "Sec-Ch-Ua-Platform"
        $any_header = /(\n)[a-zA-Z0-9\-]+:/
    condition:
        ((not $sec_ch_ua_old or (for all i in (1..#any_header): (not @sec_ch_ua_old == @any_header[i] + 1))) or (for any i in (1..#any_header): (@sec_ch_ua_new == @any_header[i] + 1))) and
        ((not $sec_ch_ua_mobile_old or (for all i in (1..#any_header): (not @sec_ch_ua_mobile_old == @any_header[i] + 1))) or (for any i in (1..#any_header): (@sec_ch_ua_mobile_new == @any_header[i] + 1))) and
        ((not $sec_ch_ua_platform_old or (for all i in (1..#any_header): (not @sec_ch_ua_platform_old == @any_header[i] + 1))) or (for any i in (1..#any_header): (@sec_ch_ua_platform_new == @any_header[i] + 1)))
}