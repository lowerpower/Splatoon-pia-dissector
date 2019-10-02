

-- ##############################
-- Pia Protocol dissector
-- ##############################
--
-- Refrence Used:
--      https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
--      https://wiki.oatmealdome.me/Pia_(Library)
--      http://mk8.tockdom.com/wiki/Talk:MK8_Network_Protocol
--      https://github.com/su63/Splatoon-Packet-Sniffing/blob/master/splatoon/splatoon/src/splatoon/NNPacket.java
--


local d = require('debug')

-- saw this in another dissector, lets you select multiple possible start sequences
-- Stole it
local possible_starts = {
    { 
        pattern = {0x32, 0xAB, 0x98, 0x64},-- Magic Number
        version = 0
    }
    , 
    { 
        pattern = {0xA1, 0xAF},-- Server to Client V0
        version = 1
    } 
}

local piaudp = Proto("piaudp","Nintendo pia protocol")

piaudp.fields.magicnumber = ProtoField.bytes("piaudp.magicnumber", "magicNumber")
piaudp.fields.packettype = ProtoField.uint8("piaudp.packettype", "packetType", base.HEX)
piaudp.fields.targetid = ProtoField.uint8("piaudp.targetid", "targetID", base.HEX )
piaudp.fields.sequencenumber = ProtoField.uint16("piaudp.sequencenumber", "sequenceNumber", base.DEC)

piaudp.fields.sourcetime = ProtoField.bytes("piaudp.sourcetime", "Source Time")
piaudp.fields.destinationtime = ProtoField.bytes("piaudp.destinationtime", "Destination Time")

piaudp.fields.iv = ProtoField.bytes("piaudp.iv", "IV")
piaudp.fields.hmac = ProtoField.bytes("piaudp.hmac", "HMAC")


function future(buffer, pinfo, tree)
-- do nothing for future
    print("future called")   
end    

function piav1(buffer, pinfo, tree)
    length = buffer:len()
    
    pinfo.cols.protocol = piaudp.name
    if length == 0 then return end    

    local subtree = tree:add(piaudp, buffer(), "PiaUDP Packet")    
    subtree:add_le(piaudp.fields.magicnumber, buffer(0,4))
    subtree:add_le(piaudp.fields.packettype, buffer(4,1))
    subtree:add_le(piaudp.fields.targetid, buffer(5,1))
    subtree:add_le(piaudp.fields.sequencenumber, buffer(6,2))    
    subtree:add_le(piaudp.fields.sourcetime, buffer(8,2))    
    subtree:add_le(piaudp.fields.destinationtime, buffer(10,2))        

    subtree:add_le(piaudp.fields.iv, buffer(12,8))      
    subtree:add_le(piaudp.fields.hmac, buffer(0x14,  16))      

end



local dissectors = {
    [0] = piav1,
    [1] = future
}

function startsWith(buffer, packet_header)
    local bytes = buffer:range(0, #packet_header.pattern):bytes()
    for i = 1, #packet_header.pattern do
        if (packet_header.pattern[i] ~= bytes:get_index(i-1)) then
            return -1
        end
    end
    return packet_header.version
end

function heuristic_piaudp(buffer, pinfo, tree)
    for i = 1, #possible_starts do
        local result = startsWith(buffer, possible_starts[i])
        if result ~= -1 then
--            print("result: " .. result)                     
            dissectors[result](buffer, pinfo, tree)            
            return true
        end
    end
    return 0
end

piaudp:register_heuristic("udp",heuristic_piaudp)


