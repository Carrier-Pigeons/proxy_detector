rule Connection_Header_Second
{
    strings:
        $any_header = /(\n)[a-zA-Z0-9\-]+:/
        $connection_header = /(\n)Connection:/

    condition:
        not $connection_header or (@any_header[2]) == @connection_header

}