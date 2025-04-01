rule Cache_Control_No_Cache
{
    strings:
        $cache_control = "\nCache-Control:" nocase
        $no_cache = "\nCache-Control:no-cache" nocase
    condition:
        not $cache_control or $no_cache
}