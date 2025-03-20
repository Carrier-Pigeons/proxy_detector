rule muraena_chromium_detected {
    strings:
        $query_param_reordered = /\?[^\s]+&page_id=\d+/ 
        $host = "Host:"
        $user_agent = "User-Agent:"
        $sec_ch_ua_capitalized = "Sec-Ch-Ua"
        $connection = "Connection:keep-alive"

    condition:
        $query_param_reordered and
        for all i in (1..#host) : (@host[i] < @user_agent[i]) and
        $sec_ch_ua_capitalized and
        not ($connection)
}
