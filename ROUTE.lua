--"C:\Program Files\Wireshark\Wireshark.exe" -X lua_script:ROUTE.lua

-- +----------------------------------------+
-- |               IP Header                |
-- +----------------------------------------+
-- |              UDP Header                |
-- +----------------------------------------+
-- |              LCT Header                |
-- +----------------------------------------+
-- |            FEC Payload Id              |
-- +----------------------------------------+
-- |           Encoding Symbols             |
-- +----------------------------------------+

-- LCT https://www.rfc-editor.org/rfc/rfc5651.html
-- ALC https://www.rfc-editor.org/rfc/rfc5775
-- FEC https://www.rfc-editor.org/rfc/rfc5052
-- GZIP https://www.rfc-editor.org/rfc/rfc1952
-- SBN/Encoding symbol ID, FEC - https://www.rfc-editor.org/rfc/rfc6330.html

route_protocol = Proto("Route",  "ROUTE Protocol") 

LCT_Version = ProtoField.uint8("route.LCT_Version", "LCT Version", base.DEC)
C = ProtoField.uint8("route.C", "Congestion control flag", base.DEC)
PSI = ProtoField.uint8("route.PSI", "Protocol-Specific Indication", base.DEC)
S = ProtoField.uint8("route.S", "Transport Session Identifier flag", base.DEC)
O = ProtoField.uint8("route.O", "Transport Object Identifier flag", base.DEC)
H = ProtoField.uint8("route.H", "Half-word flag", base.DEC)
Res = ProtoField.uint8("route.Res", "Reserved", base.DEC)
A = ProtoField.uint8("route.A", "Close Session flag", base.DEC)
B = ProtoField.uint8("route.B", "Close Object flag", base.DEC)
HDR_LEN = ProtoField.uint8("route.HDR_LEN", "LCT header length", base.DEC)
CP = ProtoField.uint8("route.CP", "Codepoint", base.DEC)
CCI = ProtoField.uint32("route.CCI", "Congestion Control Information", base.DEC)
TSI = ProtoField.uint32("route.TSI", "Transport Session Identifier", base.DEC)
TOI = ProtoField.uint32("route.TOI", "Transport Object Identifier", base.DEC)
HET = ProtoField.uint8("route.HET", "Header Extension Type", base.DEC) 
HEL = ProtoField.uint8("route.HEL", "Header Extension Length", base.DEC) 
HEC = ProtoField.bytes("route.HEC", "Header Extension Content", base.SPACE) 
SCT_Hi = ProtoField.uint8("route.SCT_Hi", "Sender Current Time High flag", base.DEC) 
SCT_Low = ProtoField.uint8("route.SCT_Low", "Sender Current Time Low flag", base.DEC) 
ERT_flag = ProtoField.uint8("route.ERT", "Expected Residual Time flag", base.DEC) 
SLC_flag = ProtoField.uint8("route.SLC", "Session Last Changed flag", base.DEC) 
Reserved = ProtoField.uint8("route.Reserved", "Reserved", base.DEC) 
PI_specific = ProtoField.uint8("route.PI_specific", "PI-specific use", base.DEC) 
SCT = ProtoField.uint64("route.SCT", "Sender Current Time", base.DEC) 
ERT = ProtoField.uint8("route.ERT_flag", "Expected Residual Time", base.DEC) 
SLC = ProtoField.uint8("route.SLC_flag", "Session Last Changed", base.DEC) 
start_offset = ProtoField.uint32("route.start_offset", "Start offset", base.DEC)
SBN = ProtoField.uint8("route.SBN", "Source Block Number", base.DEC)  
Enconding_Symbol_ID = ProtoField.uint8("route.Enconding_Symbol_ID", "Encoding Symbol ID", base.DEC)  
Payload = ProtoField.bytes("route.Payload", "Payload", base.SPACE) 

route_protocol.fields = {LCT_Version, C, PSI, S, O, H, Res, A, B, HDR_LEN, CP, CCI, TSI, TOI, HET, HEL, HEC, SCT_Hi, SCT_Low, ERT, SLC, Reserved, PI_specific, SCT, ERT_flag, SLC_flag, start_offset, SBN, Enconding_Symbol_ID, Payload}

-- create the dissection function 
function route_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = route_protocol.name

    local subtree = tree:add(route_protocol, buffer(), "ROUTE/DASH Protocol Data")

    -- to separate the bytes into bits, it converts the buffer to string and then to number
    local state = tonumber(tostring(buffer(0,1)),16)
    local LCT_Version_C_PSI = toBits(state, 8)

    -- 4 bits
    subtree:add(LCT_Version, LCT_Version_C_PSI[1]..LCT_Version_C_PSI[2]..LCT_Version_C_PSI[3]..LCT_Version_C_PSI[4]):append_text("")
    -- 2 bits
    subtree:add(C, LCT_Version_C_PSI[5]..LCT_Version_C_PSI[6])
    -- stores the value as integer for posterior use
    local CCI_len = 4*(tonumber(LCT_Version_C_PSI[5]..LCT_Version_C_PSI[6],2) + 1)
    -- 2 bits
    subtree:add(PSI, LCT_Version_C_PSI[7]..LCT_Version_C_PSI[8])

    state = tonumber(tostring(buffer(1,1)),16)
    local S_O_H_Res_A_B = toBits(state, 8)
    -- 1 bit
    subtree:add(S, S_O_H_Res_A_B[1])
    local S_int = tonumber(S_O_H_Res_A_B[1],2)

    -- 2 bits
    subtree:add(O, S_O_H_Res_A_B[2]..S_O_H_Res_A_B[3])
    local O_int = tonumber(S_O_H_Res_A_B[2]..S_O_H_Res_A_B[3],2)

    -- 1 bit
    subtree:add(H, S_O_H_Res_A_B[4])
    local H_int = tonumber(S_O_H_Res_A_B[4],2)

    -- 2 bits
    subtree:add(Res, S_O_H_Res_A_B[5]..S_O_H_Res_A_B[6])
    -- 1 bit
    subtree:add(A, S_O_H_Res_A_B[7])
    -- 1 bit
    subtree:add(B, S_O_H_Res_A_B[8])

    subtree:add(HDR_LEN, buffer(2,1))

    subtree:add(CP, buffer(3,1))

    subtree:add(CCI, buffer(4,CCI_len))

    local TSI_len = (4*S_int) + (3*H_int)
    subtree:add(TSI, buffer(4 + CCI_len, TSI_len))
    local TSI_value = tonumber(tostring(buffer(4 + CCI_len, TSI_len)), 16)

    local TOI_len = (4*O_int) + (3*H_int)
    subtree:add(TOI, buffer(4 + CCI_len + TSI_len, TOI_len))
    local TOI_value = tonumber(tostring(buffer(4 + CCI_len + TSI_len, TOI_len)), 16)

    subtree:add(HET, buffer(4 + CCI_len + TSI_len + TOI_len, 1))
    local HET_int = tonumber(tostring(buffer(4 + CCI_len + TSI_len + TOI_len, 1)), 16)

    local HEC_len
    local n_buffer
    -- HEL is present just in variable-lengh header extension
    if HET_int > 127 then
        HEC_len = 3
        n = 5
    else
        subtree:add(HEL, buffer(5 + CCI_len + TSI_len + TOI_len, 1))
        HEC_len = 4 * tonumber(tostring(buffer(5 + CCI_len + TSI_len + TOI_len, 1)), 16)
        n = 6
    end

    if HEC_len > 0 then
        subtree:add(HEC, buffer(n + CCI_len + TSI_len + TOI_len, HEC_len))
    end
    
    local position = n + HEC_len + CCI_len + TSI_len + TOI_len

    if HET_int >=2 then
        -- Use (bit field) 
        state = tonumber(tostring(buffer(position, 1)),16)
        local SCT_Hi_Low_ERT_SLC_Reserved = toBits(state, 8)

        subtree:add(SCT_Hi, SCT_Hi_Low_ERT_SLC_Reserved[1])
        local SCT_size = tonumber(SCT_Hi_Low_ERT_SLC_Reserved[1], 2)

        subtree:add(SCT_Low, SCT_Hi_Low_ERT_SLC_Reserved[2])
        SCT_size = SCT_size + tonumber(SCT_Hi_Low_ERT_SLC_Reserved[2], 2)

        subtree:add(ERT_flag, SCT_Hi_Low_ERT_SLC_Reserved[3])
        local ERT_int = tonumber(SCT_Hi_Low_ERT_SLC_Reserved[3], 10)

        subtree:add(SLC_flag, SCT_Hi_Low_ERT_SLC_Reserved[4])
        local SLC_int = tonumber(SCT_Hi_Low_ERT_SLC_Reserved[4], 10)

        subtree:add(Reserved, SCT_Hi_Low_ERT_SLC_Reserved[5]..SCT_Hi_Low_ERT_SLC_Reserved[6]..SCT_Hi_Low_ERT_SLC_Reserved[7]..SCT_Hi_Low_ERT_SLC_Reserved[8])
        local Reserved_int = tonumber(tostring(SCT_Hi_Low_ERT_SLC_Reserved[5]..SCT_Hi_Low_ERT_SLC_Reserved[6]..SCT_Hi_Low_ERT_SLC_Reserved[7]..SCT_Hi_Low_ERT_SLC_Reserved[8]), 2)
        
        position = position + 1
        subtree:add(PI_specific, buffer(position, 1))
        
        position = position + 1
        
        if SCT_size > 0 then
            subtree:add(SCT, buffer(position, 4*SCT_size))
            position = position + 4*SCT_size
        end
        
        if ERT_int == 1 then
            subtree:add(ERT, buffer(position, 4))
            position = position + 4
        end

        if SLC_int == 1 then
            subtree:add(SLC, buffer(position, 4))
            position = position + 4
        end
    end

    -- FEC => PSI field
    if tostring(LCT_Version_C_PSI[7]..LCT_Version_C_PSI[8]) == '10' then
        -- source packet
        subtree:add(start_offset, buffer(position, 4)):append_text(" source packet")
    else
        -- repair packet
        subtree:add(SBN, buffer(position, 1)):append_text(" repair packet")
        position = position + 1
        subtree:add(Enconding_Symbol_ID, buffer(position, 3))
        position = position + 3
    end

    length = length - position + 4
    position = position - 4
    subtree:add(Payload, buffer(position, length))

    -- Routine to save the data
    SaveToFile(TSI_value, TOI_value, length, position, buffer)
    --if not exists(".\\metadata") then
    --    os.execute("mkdir metadata")
    --end 
    --local filehandle = ""
    --if TSI_value == 0 then
    --    filehandle = io.open("metadata\\description_"..TSI_value, "a+")
    --else
    --    filehandle = io.open("metadata\\description_"..TSI_value.."_"..TOI_value, "a+")
    --end
    --length = length - 1
    --for i=0,length,1 
    --do
    --    local value = tonumber(tostring(buffer(position + i, 1)),16)
    --    filehandle:write(string.char(value))
    --end
    --filehandle:close()
    -------
end

function SaveToFile(TSI, TOI, length, position, buffer)
    if not exists(".\\metadata") then
        os.execute("mkdir metadata")
    end 
    local filehandle = ""
    if TSI == 0 then
        filehandle = io.open("metadata\\description_"..TSI, "a+")
    else
        filehandle = io.open("metadata\\description_"..TSI.."_"..TOI, "a+")
    end
    length = length - 1
    for i=0,length,1 
    do
        local value = tonumber(tostring(buffer(position + i, 1)),16)
        filehandle:write(string.char(value))
    end
    filehandle:close()
end 

-- Converts the number to bits (bits is the number of bits)
-- Most significant first
function toBits(num,bits)
    bits = bits or math.max(1, select(2, math.frexp(num)))
    local t = {} -- will contain the bits        
    for b = bits, 1, -1 do
        t[b] = math.fmod(num, 2)
        num = math.floor((num - t[b]) / 2)
    end
    return t
end

--- Check if a file or directory exists in this path
function exists(file)
   local ok, err, code = os.rename(file, file)
   if not ok then
      if code == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end


local udp_port = DissectorTable.get("udp.port")
-- UDP dest port
udp_port:add(6006, route_protocol)