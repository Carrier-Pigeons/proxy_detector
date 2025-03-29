rule Connection_Keep_Alive_Header_Removed
{
    strings:
        $connection_keep_alive = "Connection: keep-alive" nocase
    condition:
        not $connection_keep_alive
}