rule Host_First_UA_Second
{
    strings:
        $host_header = "Host:" nocase
        $user_agent_header = "User-Agent:" nocase
        $any_header = /(\r?\n|\n\r|\r|\n)([A-Za-z-]+:)/

    condition:
        $host_header or $user_agent_header or $any_header or
        true
}