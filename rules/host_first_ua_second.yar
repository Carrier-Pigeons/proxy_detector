rule Host_First_UA_Second
{
    strings:
        $host_header = /\nHost:/ nocase
        $user_agent_header = /\nUser-Agent:/ nocase
        $any_header = /(\n)[a-zA-Z0-9\-]+:/

    condition:
        (@any_header[1]) == @host_header and
        (@any_header[2]) == @user_agent_header

}