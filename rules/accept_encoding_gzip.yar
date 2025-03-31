rule Accept_Encoding_Gzip
{
    strings:
        $aeg = "Accept-Encoding:gzip" nocase
    condition:
        $aeg
}