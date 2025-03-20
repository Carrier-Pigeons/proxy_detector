rule tinyproxy_chromium_detected {
    strings:
        $host = "Host:"
        $user_agent = "User-Agent:"
        $connection_close = "Connection:close"
        $sec_header = "Sec-"


    condition:
        @host < @user_agent and

        $connection_close and
        not any of ($sec_header)
}