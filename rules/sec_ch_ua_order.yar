rule Sec_Ch_Ua_Headers_Order
{
    strings:
        $accept = "Accept:" nocase
        $sec_ch_ua = "sec-ch-ua" nocase
        $sec_ch_ua_mobile = "sec-ch-ua-mobile" nocase
        $sec_ch_ua_platform = "sec-ch-ua-platform" nocase
        $sec_fetch_site = "Sec-Fetch-Site:" nocase
    condition:
        for any of ($sec_ch_ua, $sec_ch_ua_mobile, $sec_ch_ua_platform) : 
            ( @ < @accept and @ > @sec_fetch_site )
}