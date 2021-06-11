-- Wireshark Dissector for HID-IO
-- Copyright 2021 Trevor Bergeron <mal@sec.gd>
-- https://github.com/half-duplex/wireshark-hid-io/
--
-- HID-IO: https://github.com/hid-io/hid-io/
-- Protocol documentation:
--  https://github.com/hid-io/hid-io-core/blob/7fc1f117f4d060368aac0b26e232bfab123009ce/hid-io-protocol/spec/README.md

local usb_interface_class_hid = 0x03

-- Packet Header
--  VVVW XYZZ [ZZZZ ZZZZ]
--  VVV - Packet Type
--    W - Continued
--    X - ID Width
--    Y - Reserved
--  ZZ+ - 2 or 10 bit packet length
-- Sync packets only require one byte (0x01100000, 0x60)

local hidio_protocol = Proto("HID-IO", "HID-IO Host-to-Device RPC")
local fields = hidio_protocol.fields

local hidio_types = {
    [0] = "Data",
    [1] = "Acknowledge",
    [2] = "Negative Acknowledge",
    [3] = "Sync",
    [4] = "Continued",
    [5] = "No Acknowledgement Data",
    [6] = "No Acknowledgement Continued",
    [7] = "Reserved",
}
--fields.header = ProtoField.ubytes("hidio.header", "Header", base.NONE)
fields.header_type = ProtoField.uint8("hidio.header.type", "Packet Type", base.DEC_HEX, hidio_types, 0xE0)
fields.header_continued = ProtoField.bool("hidio.header.continued", "Continued", 8, nil, 0x10)
fields.header_id_width = ProtoField.bool("hidio.header.id_width", "ID Width", 8, {"32-bit", "16-bit"}, 0x08)
fields.header_reserved = ProtoField.uint8("hidio.header.reserved", "Reserved", base.DEC, nil, 0x04)
fields.header_length = ProtoField.uint16("hidio.header.length", "Length", base.DEC_HEX, nil, 0x03FF)

local f_hidio_type = Field.new("hidio.header.type")
local f_hidio_continued = Field.new("hidio.header.continued")
local f_hidio_id_width = Field.new("hidio.header.id_width")
local f_hidio_length = Field.new("hidio.header.length")

-- Data
local hidio_ids = {
    [0x00] = "Supported IDs",             -- Host/Device
    [0x01] = "Get Info",                  -- Host/Device
    [0x02] = "Test Packet",               -- Host/Device
    [0x03] = "Reset HID-IO",              -- Host/Device

    [0x10] = "Get Properties",            -- Host
    [0x11] = "USB Key State",             -- Host
    [0x12] = "Keyboard Layout",           -- Host
    [0x13] = "Button Layout",             -- Host
    [0x14] = "Keycap Types",              -- Host
    [0x15] = "LED Layout",                -- Host
    [0x16] = "Flash Mode",                -- Host
    [0x17] = "UTF-8 Character Stream",    -- Device
    [0x18] = "UTF-8 State",               -- Device
    [0x19] = "Trigger Host Macro",        -- Device
    [0x1A] = "Sleep Mode",                -- Host

    [0x20] = "KLL Trigger State",         -- Device
    [0x21] = "Pixel Setting",             -- Host
    [0x22] = "Pixel Set (1ch, 8 bit)",    -- Host
    [0x23] = "Pixel Set (3ch, 8 bit)",    -- Host
    [0x24] = "Pixel Set (1ch, 16 bit)",   -- Host
    [0x25] = "Pixel Set (3ch, 16 bit)",   -- Host

    [0x30] = "Open URL",                  -- Device
    [0x31] = "Terminal Command",          -- Host
    [0x32] = "Get OS Layout",             -- Device
    [0x33] = "Set OS Layout",             -- Device
    [0x34] = "Terminal Output",           -- Device

    [0x40] = "HID Keyboard State",        -- Host/Device
    [0x41] = "HID Keyboard LED State",    -- Host/Device
    [0x42] = "HID Mouse State",           -- Host/Device
    [0x43] = "HID Joystick State",        -- Host/Device
    -- 0x44 HidSystemCtrl
    -- 0x45 HidConsumerCtrl

    [0x50] = "Manufacturing Test",        -- Host/Device
    [0x51] = "Manufacturing Test Result"  -- Host/Device
}
fields.id = ProtoField.uint32("hidio.id", "ID", base.HEX_DEC, hidio_ids)
--fields.data = ProtoField.bytes("hidio.data", "Data", base.SPACE)
fields.data = ProtoField.string("hidio.data", "Data")
fields.unknown_data = ProtoField.string("hidio.unknown_data", "Unknown Data")

local f_hidio_id = Field.new("hidio.id")

-- Command IDs
fields.terminal_command = ProtoField.string("hidio.terminal_command", "Terminal Command", base.UNICODE)

-- Expert
local ef_truncated_packet = ProtoExpert.new(
    "hidio.truncated_packet",
    "HID-IO packet truncated",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local ef_unknown_packet = ProtoExpert.new(
    "hidio.unknown_packet",
    "Unknown HID-IO packet type",
    expert.group.UNDECODED,
    expert.severity.WARN
)
local ef_invalid_packet = ProtoExpert.new(
    "hidio.invalid_packet",
    "Invalid HID-IO packet",
    expert.group.MALFORMED,
    expert.severity.WARN
)
local ef_unknown_id = ProtoExpert.new(
    "hidio.unknown_id",
    "Unknown command ID",
    expert.group.UNDECODED,
    expert.severity.WARN
)
hidio_protocol.experts = {ef_truncated_packet, ef_unknown_packet, ef_invalid_packet, ef_unknown_id}


function hidio_protocol.dissector(buffer, pinfo, tree)
    local hiddata_length = buffer:reported_length_remaining()
    if hiddata_length == 0 then return end
    -- TODO: check USB Usage Page if possible
    pinfo.cols.protocol = hidio_protocol.name

    -- Multiple packets per interrupt is not allowed by the spec, but broken
    -- implementations sometimes send fragments after the first, so show them.
    local packet_offset = 0
    while packet_offset < hiddata_length do
        local offset = packet_offset
        local hiddata_left = hiddata_length - offset

        -- peek at length fields so we create the correct subtrees
        local header_length, claimed_data_length
        if bit.rshift(bit.band(buffer(offset,1):uint(), 0xE0), 5) == 3 then
            -- sync packet, one byte
            header_length = 1
            claimed_data_length = 0
        else
            if hiddata_left > 1 then
                header_length = 2
                claimed_data_length = bit.band(buffer(offset,2):uint(), 0x03FF)
            else
                -- parse the one byte
                header_length = 1
                -- minimum claimed data length, from 2 MSBits
                claimed_data_length = bit.lshift(bit.band(buffer(offset,1):uint(), 0x03), 8)
            end
        end

        packet_offset = packet_offset + claimed_data_length + header_length -- for next loop
        local packet_length = math.min(claimed_data_length, hiddata_left - header_length)

        -- create trees
        local subtree = tree:add(hidio_protocol, buffer(offset, packet_length), "HID-IO")
        local headertree = subtree:add(hidio_protocol, buffer(offset, header_length), "Header")

        -- always-present header byte
        headertree:add(fields.header_type, buffer(offset,1))
        local hidio_type = select(-1, f_hidio_type())
        subtree:append_text(": " .. hidio_type.display)
        headertree:add(fields.header_continued, buffer(offset,1))
        local hidio_continued = select(-1, f_hidio_continued())
        if hidio_continued.value then
            headertree:append_text(": Continued")
        else
            headertree:append_text(": Final")
        end
        headertree:add(fields.header_id_width, buffer(offset,1))
        local hidio_id_width = select(-1, f_hidio_id_width())
        headertree:append_text(", " .. hidio_id_width.display .. " IDs")
        headertree:add(fields.header_reserved, buffer(offset,1))
        if select(-1, f_hidio_type()).value == 3 then goto continue end -- sync packet, only 1 byte

        -- length field LSB
        headertree:add(fields.header_length, buffer(offset,2))
        headertree:append_text(", Length: " .. claimed_data_length)
        offset = offset + 2 -- flags+length

        -- detect truncated packet
        if packet_length ~= claimed_data_length then
            local missing = claimed_data_length - packet_length
            subtree:add_proto_expert_info(
                ef_truncated_packet,
                "HID-IO packet truncated ("..missing.."+ bytes short)"
            )
        end

        -- detect zero-fill at end of some packets
        if claimed_data_length < 2 then -- invalid for all non-sync types
            subtree:add_proto_expert_info(ef_invalid_packet, "Invalid HID-IO packet length")
            return
        end

        -- command ID
        local id_bytes = hidio_id_width() and 4 or 2
        hiddata_left = hiddata_length - offset
        if hiddata_left < id_bytes then return end -- truncated here?
        subtree:add_le(fields.id, buffer(offset, id_bytes))
        local hidio_id = select(-1, f_hidio_id()).value
        packet_length = packet_length - id_bytes
        offset = offset + id_bytes

        hiddata_left = hiddata_length - offset
        if hidio_type.value == 0 then -- data
            if hidio_id == 0x31 then -- (Host) Terminal Command
                subtree:add_le(fields.terminal_command, buffer(offset, packet_length))
            else
                subtree:add_proto_expert_info(ef_unknown_id)
                subtree:add_le(fields.data, buffer(offset, packet_length))
            end
        elseif hidio_type.value == 1 then -- ack
        elseif hidio_type.value == 2 then -- nack
        elseif hidio_type.value == 4 then -- cont
        elseif hidio_type.value == 5 then -- no ack data
        elseif hidio_type.value == 6 then -- no ack cont
        else -- reserved
            subtree:add_proto_expert_info(ef_unknown_packet)
        end

        ::continue::
    end
end

DissectorTable.get("usb.interrupt"):add(usb_interface_class_hid, hidio_protocol)
