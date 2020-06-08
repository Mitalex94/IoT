-- existed fields
local f_wpan_nwksrc64    = Field.new("wpan.src64")
local f_wpan_nwksrc16    = Field.new("wpan.src16")
local f_wpan_nwkdst64    = Field.new("wpan.dst64")
local f_wpan_nwkdst16    = Field.new("wpan.dst16")
local f_zbee_nwksrc64    = Field.new("zbee_nwk.src64")
local f_zbee_nwkdst64    = Field.new("zbee_nwk.dst64")
local f_zbee_nwkdst      = Field.new("zbee_nwk.dst")
local f_zbee_nwksrc      = Field.new("zbee_nwk.src")
local f_Protocols        = Field.new("frame.Protocols")
local f_framenr          = Field.new("frame.number")

-- creating zbee protocol
local zbee_Protocol = Proto("zbee", "WPAN Lookup")


local f_srcname = ProtoField.string("zbee.srcname", "SrcName")
local f_src     = ProtoField.string("zbee.src", "Src")
local f_dstname = ProtoField.string("zbee.dstname", "DstName")
local f_dst     = ProtoField.string("zbee.dst", "Dst")
local f_test     = ProtoField.string("zbee.test", "Test")


zbee_Protocol.Fields = {
    f_dstname,
    f_dst,
    f_srcname,
    f_src,
    f_test,
}


function split(s, delimiter)
    result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match);
    end
    return result;
end


function ChangeAddress(address)
    address = string.gsub(string.lower(address), "0x0000", "0x")
    
    if address == "0x" then address="0x0000" end
    return address
end 


function GetFileName()
   local str = debug.getinfo(2, "S").source:sub(2)
   return tostring( str:match("(.*)(lua)").."lookup.csv" ) 
end


function ReadLookup()  
    lookup_table = {}
    for line in io.lines( GetFileName() ) do 
        lookup_table[#lookup_table + 1] = split(line,",")
    end
    
    return lookup_table
end


function GetLookup(zbee_address)
    local name = GetLookup64(zbee_address)
    if name == "" then 
        name = GetLookup16(zbee_address) 
    end
    return name
end


function GetLookup64(zbee_address)
    for count = 1, #lookup_table do
        if string.lower(lookup_table[count][1]) == string.lower(zbee_address) then
            return lookup_table[count][3]
        end
    end
    
    return ""
end


function GetLookup16(zbee_address)
    for count = 1, #lookup_table do
        if string.lower(lookup_table[count][2]) == string.lower(zbee_address) or string.lower(lookup_table[count][2]) == string.gsub(string.lower(zbee_address), "0x0000", "0x") then
            return lookup_table[count][3]
        end
    end
    
    return ""
end


local lookup = ReadLookup()


function zbee.dissector(tvb, pinfo, tree)
    if string.find(tostring( f_Protocols() ), "wpan") ~= 1 then
        return         
    end
      
    local subtree = tree:add(zbee)
    
    local src = f_zbee_nwksrc64() or f_wpan_nwksrc64() or f_wpan_nwksrc16()
    src = tostring( src )

    local dst = f_zbee_nwkdst64() or f_wpan_nwkdst64() or f_wpan_nwkdst16()
    dst = tostring( dst )

    subtree:add(f_src, ChangeAddress(src) )
    subtree:add(f_srcname, GetLookup(src) )
    subtree:add(f_dst, ChangeAddress(dst) )
    subtree:add(f_dstname, GetLookup(dst) )
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8051, zbee_Protocol)

