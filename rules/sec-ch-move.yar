// sec-ch-ua, sec-ch-ua-mobile, & 
// sec-ch-ua-platform moved from after Cache-control (or Connection) 
// and before DNT to after Accept & before Sec-Fetch-Site

rule Host_First_UA_Second
{
    strings:
        $sec_ch_ua_header = /\nsec-ch-ua:/ nocase
        $sec_ch_ua_mobile_header = /\nsec-ch-ua-mobile:/ nocase
        $sec_ch_ua_platform_header = /\nsec-ch-ua-platform:/ nocase
        $sec_fetch_site_header = /\nSec-Fetch-Site:/ nocase
        $accept_header = /\nAccept:/ nocase

    condition:
        not $sec_fetch_site_header or
        not $accept_header or
        (
        (not $sec_ch_ua_header or (@sec_fetch_site_header > @sec_ch_ua_header and @accept_header < @sec_ch_ua_header)) and
        (not $sec_ch_ua_mobile_header or (@sec_fetch_site_header > @sec_ch_ua_mobile_header and @accept_header < @sec_ch_ua_mobile_header)) and
        (not $sec_ch_ua_platform_header or (@sec_fetch_site_header > @sec_ch_ua_platform_header and @accept_header < @sec_ch_ua_platform_header))
        )
        

}