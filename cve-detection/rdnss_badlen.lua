-- rdnss_badlen.lua
-- Detects ICMPv6 Router Advertisement with RDNSS option (type 25)
-- where the option Length is invalid: <3 or not an odd number ((len-1)/2 must be integer >=1).
-- RFC 8106 requires Length >= 3 and (Length-1) divisible by 2.
function init (args)
    local needs = {}
    needs["packet"] = tostring(True)
    return needs
end

local function u8(str, off) return string.byte(str, off) end

function match (args)
    local p = args["payload"]
    if p == nil then return 0 end
    local len = #p
    if len < 16 then return 0 end
    local icmp_type = u8(p, 1)
    if icmp_type ~= 134 then return 0 end  -- RA

    -- Skip ICMPv6 header(4) + RA fixed fields(12) = 16 bytes
    local off = 16
    while off + 1 <= len do
        local opt_type = u8(p, off + 1)
        local opt_len_units = u8(p, off + 2)
        if opt_len_units == 0 then return 0 end
        local opt_total = opt_len_units * 8
        if off + opt_total > len then return 0 end
        if opt_type == 25 then
            if opt_len_units < 3 then return 1 end
            local addr_units = opt_len_units - 1
            if (addr_units % 2) ~= 0 then return 1 end
            if addr_units < 2 then return 1 end
            return 0
        end
        off = off + opt_total
        if opt_total == 0 then break end
    end
    return 0
end
