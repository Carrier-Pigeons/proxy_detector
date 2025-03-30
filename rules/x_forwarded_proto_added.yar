rule X_Forwarded_Proto_Added
{
    strings:
        $x_forwarded_proto_header = "x-forwarded-proto:" nocase
    condition:
        $x_forwarded_proto_header
}