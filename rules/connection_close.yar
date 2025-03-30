rule Connection_Close
{
    strings:
        $connection_close = "Connection:close" nocase
    condition:
        $connection_close
}