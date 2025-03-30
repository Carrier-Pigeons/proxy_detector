rule Connection_Close
{
    strings:
        $connection_header = "Connection:" nocase
        $connection_close = "close"
    condition:
        not $connection_header or $connection_close at (@connection_header + 11)
}