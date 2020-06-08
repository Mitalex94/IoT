thread_Protocol = Proto("thread", "Thread Protocol")  

packettypes = { "Ping request", "Ping acknowledgment", "Print payload" }
packetbool  = { [0] = "False",  "True" }

local thread_hdr_version = ProtoField.uint8("thread.hdr.version", 
                      "Thread Header Version", base.DEC, {"Version 1"})

local thread_hdr_type    = ProtoField.uint8("thread.hdr.type", 
                      "Thread Header Type",    base.DEC, packettypes)

local threadhdr_flags   = ProtoField.uint8("thread.hdr.flags", "Thread Header Flags", base.HEX)

local thread_hdr_flags_first   = ProtoField.uint8("thread.hdr.flags.first",   
                            "Thread first flag",   base.DEC, packetbool, 0x01)
local thread_hdr_flags_second  = ProtoField.uint8("thread.hdr.flags.second",  
                            "Thread second flag",  base.DEC, packetbool, 0x02)
local thread_hdr_flags_onemore = ProtoField.uint8("thread.hdr.flags.onemore", 
                            "Thread onemore flag", base.DEC, packetbool, 0x04)

local threadhdr_bool = ProtoField.bool  ("thread.hdr.bool", "Thread Header Boolean")
local threadpl_len   = ProtoField.uint32("thread.pl_len",   "Thread Payload Length")
local threadpayload  = ProtoField.string("thread.payload",  "Thread Payload", base.STRING)

thread_Protocol.fields = { thread_hdr_version,     thread_hdr_type,         thread_hdr_flags,
                 thread_hdr_flags_first, thread_hdr_flags_second, thread_hdr_flags_onemore,
                 thread_hdr_bool,        thread_pl_len,           thread_payload }

-- Функция диссектора для протокола Thread
function thread_Protocol.dissector(buf, pinfo, tree)
    if buf:len() == 0 then return end
    pinfo.cols.protocol = thread_Protocol.name       

    subtree = tree:add(thread_Protocol, buf(0))    


    subtree:add(thread_hdr_version, buf(0,1)) 
    local ver = buf(0,1):uint()
 

    if ver == 1 then
       local type_str = packettypes[buf(1,1):uint()]
       if type_str == nil then type_str = "Unknown" end
       pinfo.cols.info = "Type: " .. type_str   -- в колонке Info будет отображаться тип пакета
       subtree:add(thread_hdr_type,  buf(1,1))
       subtree:add(thread_hdr_flags,         buf(2,1))
       subtree:add(thread_hdr_flags_first,   buf(2,1))
       subtree:add(thread_hdr_flags_second,  buf(2,1))
       subtree:add(threadh_dr_flags_onemore, buf(2,1))
       subtree:add(thread_hdr_bool,  buf(3,1))
       subtree:add_le(thread_pl_len, buf(4,4))  

       local pl_len = buf(4,4):le_uint()
       subtree:add(thread_payload, buf(8,pl_len))  
    else
       subtree:append_text(string.format(", Unknown version of Thread protocol (0x%02x)", ver))
    end
end

local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(11849, thread_Protocol)