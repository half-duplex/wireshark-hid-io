# Wireshark HID-IO
A basic, partial Lua dissector for [HID-IO](https://github.com/hid-io/hid-io/)

![dissected hid-io screenshot](https://user-images.githubusercontent.com/1053010/121633069-adbea600-ca71-11eb-8569-7fe8327c49a2.png)

## Installation
Download
[hid-io.lua](https://github.com/half-duplex/wireshark-hid-io/blob/main/hid-io.lua)
to your Wireshark plugins folder, e.g.  `~/.local/lib/wireshark/plugins/`,
ensure Lua is enabled, and (re)start Wireshark.

Further details are available on the Wireshark Wiki's
[Lua Support page](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)

## Usage
This dissector currently only understands HID-IO over USB, and is not
particularly selective for what it attempts to parse. If you use Wireshark for
other USB interrupt traffic, you should probably disable it when not in use.
