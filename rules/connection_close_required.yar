rule Connection_Close_Required
{
    strings:
        $connection_header = "Connection:close" nocase
    condition:
        $connection_header
}