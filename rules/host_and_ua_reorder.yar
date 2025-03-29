rule Host_and_UA_Reordered
{
    strings:
        $host_header = "Host:" nocase
        $user_agent_header = "User-Agent:" nocase
    condition:
        $host_header at 0 and $user_agent_header at 1
}