-- Lua Dissector for ROUTE Protocol ATSC 3.0
-- Author: Rodrigo Vaz (radvaz@gmail.com)

--    it under the terms of the GNU General Public License as published by
--    This program is free software: you can redistribute it and/or modify
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Execute  
-- C:\Program Files\Wireshark>Wireshark.exe -X lua_script:route.lua

-- Standards:
-- ATSC Standard: Signaling, Delivery, Synchronization, and Error Protection (https://muygs2x2vhb2pjk6g160f1s8-wpengine.netdna-ssl.com/wp-content/uploads/2021/10/A331-2021-Signaling-Delivery-Sync-FEC-With-Amend-1-2-3-4.pdf)
-- Guidelines for Implementation: DASH-IF Interoperability Point for ATSC 3.0 (https://dashif.org/docs/DASH-IF-IOP-for-ATSC3-0-v1.1.pdf)
-- Layered Coding Transport (LCT) Building Block (https://www.rfc-editor.org/rfc/rfc5651.html)
-- Asynchronous Layered Coding (ALC) Protocol Instantiation (https://datatracker.ietf.org/doc/html/rfc5775)
-- Creating a Wireshark dissector in Lua - part 1 (the basics) (https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
-- Chapter 9. Packet Dissection (https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html)

--Filtro Wireshark  
--route.TOI == 2 && route.TSI ==100 => TOI == 2 => second ISOBMFF segment || TSI == 100 (0x64)=> BL || TSI == 101 (0x65) => EL

-- declare the protocol
route_protocol = Proto("Route",  "Route Protocol") 

LCT_version_C_PSI = ProtoField.uint8("route.LCT_version_C_PSI", "LCT_version_C_PSI", base.DEC) -- decimal value
--LCT_version_C_PSI = ProtoField.uint8("route.LCT_version_C_PSI", "LCT_version_C_PSI", base.HEX) -- hexadecimal
-- colocar mascara "and" filtro

S_O_H_Res_A_B = ProtoField.uint8("route.S_O_H_Res_A_B", "S_O_H_Res_A_B", base.DEC) 

HDR_LEN = ProtoField.uint8("route.HDR_LEN", "HDR_LEN", base.DEC) 

Codepoint 	= ProtoField.uint8("route.Codepoint", "Codepoint (CP)", base.DEC)

CCI 		= ProtoField.uint32("route.CCI", "CCI", base.DEC)  

TSI 		= ProtoField.uint32("route.TSI", "TSI", base.DEC) 

TOI 		= ProtoField.uint32("route.TOI", "TOI", base.DEC) 

HET 		= ProtoField.uint8("route.HET", "HET", base.DEC) 

HEL 		= ProtoField.uint8("route.HEL", "HEL", base.DEC) 

--HEC 		= ProtoField.uint64("route.HEC", "HEC", base.DEC) 
HEC 		= ProtoField.bytes ("route.HEC", "HEC", base.SPACE) 

Payload = ProtoField.bytes("route.Payload", "Route payload", base.SPACE) 

route_protocol.fields = {LCT_version_C_PSI, S_O_H_Res_A_B, HDR_LEN, Codepoint, CCI, TSI, TOI, HET, HEL, HEC, Payload}

-- create the dissection function 
function route_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = route_protocol.name

  -- creates Route Protocol Data subtree
  local subtree = tree:add(route_protocol, buffer(), "Route Protocol Data") -- adds "Route Protocol Data" on the protocols tree
      
  --subtree:add_le(LCT_version_C_PSI, buffer(0,1)) -- little_endian
  subtree:add(LCT_version_C_PSI, buffer(0,1)) --endian
  
  subtree:add(S_O_H_Res_A_B, buffer(1,1)) 
  
  subtree:add(HDR_LEN, 			buffer(2,1)):append_text(" (HDR_LEN == 8 => 36 bytes header | HDR_LEN == 4 => 20 bytes header)")  
  
  subtree:add(Codepoint, 		buffer(3,1)):append_text(" (CP == 8 => A/V segments | CP == 0 => XML files )") 
  
  subtree:add(CCI, 				buffer(4,4)) 
  
  subtree:add(TSI, 				buffer(8,4)):append_text(" (TSI == 0 => XML files | TSI == 100 => BL | TSI == 101 => EL | TSI == 200 => audio)") 
  
  subtree:add(TOI, 				buffer(12,4)):append_text(" (original segment number)") 
  
  subtree:add_le(HET, 			buffer(16,1)):append_text(" (HET == 64 => EXT_FTI (FEC) | HET == 0 => EXT_NOP (No-Operation extension))") 
  
  -- Estabelecer condição em cima do HDR_LEN -- HDR_LEN == 8 => cabeçalho de 36 bytes | HDR_LEN == 04  => cabeçalho de 20 bytes
  local HDR_LEN1 = buffer(2,1):int()
  if HDR_LEN1 == 8 then 
	subtree:add(HEL, 			buffer(17,1)):append_text(" (HEL == 4 => 20 bytes header counted from TOI field)") 
	subtree:add(HEC,			buffer(18,18)):append_text(" (FEC)")
	subtree:add(Payload,		buffer(36, length-36))
		  
  else
	subtree:add(HEL, 			buffer(17,1)):append_text(" (fragment order)") 
	subtree:add(HEC, 			buffer(18,2)):append_text(" (HEX - fragment order)") 
	subtree:add(Payload,		buffer(20,length-20))
  end 
  
  -- Identificacar ROUTE payload no subtree e selecionar somente o payload
  
end

-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(59274, mongodb_protocol)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(6002, route_protocol) -- porta UDP 6002