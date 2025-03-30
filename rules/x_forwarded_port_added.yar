rule X_Forwarded_Port_Added
{
    strings:
        $x_forwarded_port = "x-forwarded-port:" nocase
    condition:
        $x_forwarded_port
}