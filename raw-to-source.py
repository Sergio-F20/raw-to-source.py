import argparse
import os

def read_shellcode(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def convert_to_hex(binary_data):
    return binary_data.hex()

def format_for_c(hex_data):
    formatted_string = "unsigned char buf[] = \n"
    line = ""
    for i in range(0, len(hex_data), 2):
        byte = f"\\x{hex_data[i:i+2]}"
        if len(line) + len(byte) > 58:
            formatted_string += "\"" + line + "\"\n"
            line = byte
        else:
            line += byte
    formatted_string += "\"" + line + "\";"
    return formatted_string

def format_for_powershell(hex_data):
    formatted_string = "[Byte[]] $buf = "
    hex_pairs = [f"0x{hex_data[i:i+2]}" for i in range(0, len(hex_data), 2)]
    formatted_string += ",".join(hex_pairs)
    return formatted_string

def format_for_csharp(hex_data):
    hex_pairs = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
    formatted_string = "byte[] buf = new byte[" + str(len(hex_pairs)) + "] {\n"
    
    for i, hex_pair in enumerate(hex_pairs):
        formatted_string += "0x" + hex_pair
        if (i + 1) % 12 == 0:
            formatted_string += ",\n"
        elif (i + 1) < len(hex_pairs):
            formatted_string += ","
    
    formatted_string += "\n};"
    
    return formatted_string

def main():
    parser = argparse.ArgumentParser(description="Shellcode to Source Code Converter",
                                     epilog="Example: python script.py -r raw-shellcode.bin --format c/ps/csharp -o output-file")
    parser.add_argument("-r", "--raw", required=True, help="Path to the binary shellcode file")
    parser.add_argument("--format", "-f", choices=['c', 'ps', 'powershell', 'csharp', 'cs'], 
                        help="Output format: c, ps (or powershell), csharp (or cs)", required=True)
    parser.add_argument("-o", "--output", help="Output file name")

    args = parser.parse_args()

    if not os.path.exists(args.raw):
        print(f"Error: File {args.raw} does not exist")
        return

    binary_data = read_shellcode(args.raw)
    hex_data = convert_to_hex(binary_data)

    if args.format == 'c':
        code = format_for_c(hex_data)

    elif args.format == 'ps' or args.format == 'powershell':
        code = format_for_powershell(hex_data)

    elif args.format == 'csharp' or args.format == 'cs':
        code = format_for_csharp(hex_data)

    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write(code)
    else:
        print(code)

if __name__ == "__main__":
    main()
