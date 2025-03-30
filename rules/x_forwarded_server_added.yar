rule X_Forwarded_Server_Header_Added
{
    strings:
        $x_forwarded_server_header = "x-forwarded-server:" nocase
    condition:
        $x_forwarded_server_header
}