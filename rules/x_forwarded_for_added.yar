rule X_Forwarded_For_Header_Added
{
    strings:
        $x_forwarded_for_header = "x-forwarded-for:" nocase
    condition:
        $x_forwarded_for_header
}