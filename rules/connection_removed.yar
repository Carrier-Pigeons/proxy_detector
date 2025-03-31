rule Connection_Header_Removed
{
    strings:
        $connection = "Connection:" nocase
    condition:
        not $connection
}