Usage

wsmask -t|b -m|u [-k xxxxxxxx] -i input.bin -o output.bin

    -t set opcode to text
    -b set opcode to binary (default)
    -m add websocket header and mask payload
    -u unmask payload
    -k xxxxx masking key used with -m option
    -i input.bin
    -o output.bin

You can use the following commands to convert each other.

    $ ./wsmask -u -i sample/masked.bin -o unmasked.bin
    $ ./wsmask -m -k deadbeef -i sample/unmasked.txt -o masked.bin
