rule Host_And_Ua_Reorder
{
    strings:
        $host_header = "Host:"
        $user_agent_header = "User-Agent:"
        $accept = "Accept:"

    condition:
        @host_header < @user_agent_header and
        @user_agent_header < @accept
    
}