rule All_Header_Lowercase
{
    strings:
        $any_header = /(\n)[a-zA-Z0-9\-]+:/
        $any_header_lower = /(\n)[a-z0-9\-]+:/

    condition:
        #any_header == #any_header_lower
}