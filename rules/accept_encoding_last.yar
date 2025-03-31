rule Accept_Encoding_Last
{
    strings:
        $accept_encoding_header = /\nAccept-Encoding:/ nocase
        $any_header = /(\n)[a-zA-Z0-9\-]+:/

    condition:
        #accept_encoding_header > 0 and #any_header > 0 and
        @accept_encoding_header[#accept_encoding_header] == @any_header[#any_header]
}