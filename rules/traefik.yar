rule traefik_chromium_detected {
    strings:
        $x_forwarded_for = "X-Forwarded-For:"
        $x_forwarded_host = "X-Forwarded-Host:"
        $x_forwarded_port = "X-Forwarded-Port:"
        $x_forwarded_proto = "X-Forwarded-Proto:"
        $x_real_ip = "X-Real-Ip:"
        
        $dnt_lower = "Dnt:"
        $sec_ch_ua = "Sec-Ch-Ua:"

        $connection = "Connection: keep-alive"
        $cookie = "Cookie:"

    condition:
        all of ($x_*) and
        any of ($dnt_lower, $sec_ch_ua) and
        not any of ($connection, $cookie)
}
