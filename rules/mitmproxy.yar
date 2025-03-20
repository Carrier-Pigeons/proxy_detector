rule mitmproxy_chromium_detected {
    strings:
        $pragma_no_cache = "Pragma:no-cache"
        $cache_control_no_cache = "Cache-Control:no-cache"
        $accept = "Accept:"
        $sec_fetch_site = "Sec-Fetch-Site:"
        $dnt = "DNT"

    condition:
        @pragma_no_cache < @cache_control_no_cache and 
        @cache_control_no_cache < @dnt and
        @accept < @sec_fetch_site
}