rule X_Forwarded_For_Last
{
    strings:
        $x_forwarded_for_header = /\nX-Forwarded-For:/ nocase
        $any_header = /(\n)[a-zA-Z0-9\-]+:/

    condition:
        #x_forwarded_for_header > 0 and #any_header > 0 and
        @x_forwarded_for_header[#x_forwarded_for_header] == @any_header[#any_header]
}