rule X_Forwarded_Host_Header_Added
{
    strings:
        $x_forwarded_host_header = "x-forwarded-host:" nocase
    condition:
        $x_forwarded_host_header
}