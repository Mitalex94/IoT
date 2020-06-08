modbus_Protocol = Proto("modbus",  "modbus Protocol")

-- header
message_length  = ProtoField.int32 ("modbus.message_length"  , "messageLength"     , base.DEC)
request_id      = ProtoField.int32 ("modbus.requestid"       , "requestID"         , base.DEC)
response_to     = ProtoField.int32 ("modbus.responseto"      , "responseTo"        , base.DEC)
opcode          = ProtoField.int32 ("modbus.opcode"          , "opCode"            , base.DEC)

-- payload 
flags           = ProtoField.int32 ("modbus.flags"           , "flags"             , base.DEC)
full_coll_name  = ProtoField.string("modbus.full_coll_name"  , "fullCollectionName", base.ASCII)
number_to_skip  = ProtoField.int32 ("modbus.number_to_skip"  , "numberToSkip"      , base.DEC)
number_to_return= ProtoField.int32 ("modbus.number_to_return", "numberToReturn"    , base.DEC)
query           = ProtoField.none  ("modbus.query"           , "query"             , base.HEX)

response_flags  = ProtoField.int32 ("modbus.response_flags"  , "responseFlags"     , base.DEC)
cursor_id       = ProtoField.int64 ("modbus.cursor_id"       , "cursorId"          , base.DEC)
starting_from   = ProtoField.int32 ("modbus.starting_from"   , "startingFrom"      , base.DEC)
number_returned = ProtoField.int32 ("modbus.number_returned" , "numberReturned"    , base.DEC)
documents       = ProtoField.none  ("modbus.documents"       , "documents"         , base.HEX)

modbus_Protocol.fields = {
  message_length, request_id, response_to, opcode,                     -- header
  flags, full_coll_name, number_to_skip, number_to_return, query,      -- OP_QUERY
  response_flags, cursor_id, starting_from, number_returned, documents -- OP_REPLY
}

function modbus_Protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.Protocol = modbus_Protocol.name

    local        subtree =    tree:add(modbus_Protocol, buffer(), "modbus Protocol Data")
    local  headerSubtree = subtree:add(modbus_Protocol, buffer(), "header")
    local payloadSubtree = subtree:add(modbus_Protocol, buffer(), "payload")

    -- header
    headerSubtree:add_le(message_length, buffer(0,4))
    headerSubtree:add_le(request_id,     buffer(4,4))
    headerSubtree:add_le(response_to,    buffer(8,4))

    local opcode_number = buffer(12,4):le_uint()
    local opcode_name = get_opcode_name(opcode_number)
    headerSubtree:add_le(opcode,         buffer(12,4)):append_text(" (" .. opcode_name .. ")")

    -- payload
    if opcode_name == "OP_QUERY" then
        local flags_number = buffer(16,4):le_uint()
        local flags_description = get_flag_description(flags_number)
        payloadSubtree:add_le(flags,      buffer(16,4)):append_text(" (" .. flags_description .. ")")

        
        local string_length
        for i = 20, length - 1, 1 do
            if (buffer(i,1):le_uint() == 0) then
                string_length = i - 20
                break
            end
        end

        payloadSubtree:add_le(full_coll_name,   buffer(20,string_length))
        payloadSubtree:add_le(number_to_skip,   buffer(20+string_length,4))
        payloadSubtree:add_le(number_to_return, buffer(24+string_length,4))
        payloadSubtree:add_le(query,            buffer(28+string_length,length-string_length-28))
    elseif opcode_name == "OP_REPLY" then
        local response_flags_number = buffer(16,4):le_uint()
        local response_flags_description = get_response_flag_description(response_flags_number)

        payloadSubtree:add_le(response_flags,   buffer(16,4)):append_text(" (" .. response_flags_description .. ")")
        payloadSubtree:add_le(cursor_id,        buffer(20,8))
        payloadSubtree:add_le(starting_from,    buffer(28,4))
        payloadSubtree:add_le(number_returned,  buffer(32,4))
        payloadSubtree:add_le(documents,        buffer(36,length-36))
    end
end

function get_opcode_name(opcode)
    local opcode_name = "Unknown"

	    if opcode ==    1 then opcode_name = "OP_REPLY"
	elseif opcode == 2001 then opcode_name = "OP_UPDATE"
    elseif opcode == 2002 then opcode_name = "OP_INSERT"
    elseif opcode == 2003 then opcode_name = "RESERVED"
    elseif opcode == 2004 then opcode_name = "OP_QUERY"
    elseif opcode == 2005 then opcode_name = "OP_GET_MORE"
    elseif opcode == 2006 then opcode_name = "OP_DELETE"
    elseif opcode == 2007 then opcode_name = "OP_KILL_CURSORS"
    elseif opcode == 2010 then opcode_name = "OP_COMMAND"
    elseif opcode == 2011 then opcode_name = "OP_COMMANDREPLY" end

    return opcode_name
end

function get_flag_description(flags)
    local flags_description = "Unknown"

        if flags == 0 then flags_description = "Reserved"
    elseif flags == 1 then flags_description = "TailableCursor"
    elseif flags == 2 then flags_description = "SlaveOk.Allow"
    elseif flags == 3 then flags_description = "OplogReplay"
    elseif flags == 4 then flags_description = "NoCursorTimeout"
    elseif flags == 5 then flags_description = "AwaitData"
    elseif flags == 6 then flags_description = "Exhaust"
    elseif flags == 7 then flags_description = "Partial"
    elseif 8 <= flags and flags <= 31 then flags_description = "Reserved" end

    return flags_description
end

function get_response_flag_description(flags)
    local flags_description = "Unknown"

        if flags == 0 then flags_description = "CursorNotFound"
    elseif flags == 1 then flags_description = "QueryFailure"
    elseif flags == 2 then flags_description = "ShardConfigStale"
    elseif flags == 3 then flags_description = "AwaitCapable"
    elseif 4 <= flags and flags <= 31 then flags_description = "Reserved" end

    return flags_description
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(502, modbus_Protocol)
