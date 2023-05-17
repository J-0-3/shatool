import argparse
import base64
import sha_functions

def calc_hash(args):
    if args.file:
        with open(args.file, 'rb') as f:
            data = f.read()
    elif args.hex:
        data = bytes.fromhex(args.hex)
    elif args.base64:
        data = base64.b64decode(args.base64)
    elif args.str:
        data = args.str.encode('utf-8')
    digest = sha_functions.sha256(data)
    match args.output_format:
        case "hex":
            print(digest.hex())
        case "b64":
            print(base64.b64encode(digest).decode('utf-8'))
        case "dec":
            print(int.from_bytes(digest))
        case "raw":
            print(digest)

def extend_hash(args):
    match args.hash_format:
        case "hex":
            initial_digest = bytes.fromhex(args.hash)
        case "b64":
            initial_digest = base64.b64decode(args.hash)
        case "dec":
            initial_digest = int(args.hash).to_bytes(32)
    match args.data_format:
        case "file":
            with open(args.data_to_append, 'rb') as f:
                to_append = f.read()
        case "hex":
            to_append = bytes.fromhex(args.data_to_append)
        case "b64":
            to_append = base64.b64decode(args.data_to_append)
        case "str":
            to_append = args.data_to_append.encode('utf-8')
    actual_data_appended, final_digest = sha_functions.length_extend(initial_digest, args.data_length, to_append)
    print("Actual data that was appended was: ")
    print(actual_data_appended)
    print("Calculated Hash: ") 
    match args.output_format:
        case "hex":
            print(final_digest.hex())
        case "b64":
            print(base64.b64encode(final_digest))
        case "dec":
            print(int.from_bytes(final_digest))
        case "raw":
            print(final_digest)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("shatool", description="Multipurpose tool for operations and attacks relating to the SHA256 hashing algorithm")
    subparsers = parser.add_subparsers(title="subcommands")
    parser_calc = subparsers.add_parser("calc", help="Calculate the SHA256 hash of some data")
    parser_calc.set_defaults(func=calc_hash)
    g = parser_calc.add_mutually_exclusive_group(required=True)
    g.add_argument("-f", "--file", help="File name containing the data", type=str)
    g.add_argument("-x", "--hex", help="Input data represented as a hexstring", type=str)
    g.add_argument("-b64", "--base64", help="Input data represented as a base64 string", type=str)
    g.add_argument("-s", "--str", help="Input data represented as a UTF-8 string", type=str)
    parser_calc.add_argument("-of", "--output-format", type=str, default="hex", choices=["hex", "b64", "dec", "raw"])
    parser_extend = subparsers.add_parser("extend", help="Perform a length extension attack", epilog="Given the hash of some unknown data and the length of that data, calculates the hash of the original data + some arbitrary data.\nIt is important to remember that the SHA padding of the original data will be included in the calculation of the hash and so should be treated as part of the data itself.")
    parser_extend.set_defaults(func=extend_hash)
    parser_extend.add_argument("-hf", "--hash-format", type=str, default="hex", choices=["hex", "b64", "dec"], help="The format the initial hash is given as")
    parser_extend.add_argument("hash", type=str, help="The initial hash of the original (unknown) data")
    parser_extend.add_argument("data_length", type=int, help="The length of the original data")
    parser_extend.add_argument("-of", "--output-format", type=str, default="hex", choices=["hex", "b64", "dec", "raw"], help="The format in which to output the final calculated hash")
    parser_extend.add_argument("-if", "--data-format", type=str, choices=["file", "hex", "b64", "str"], required=True, help="The format which the data to append is given as")
    parser_extend.add_argument("data_to_append", type=str, help="The additional data to append to the end of the original unknown data")
    #parser_crack = subparsers.add_parser("crack", help="Attempt to crack a SHA hash")
    args = parser.parse_args() 
    try:
        args.func(args)
    except AttributeError:
        parser.print_help()
