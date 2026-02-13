#!/usr/bin/env python3

import sys

from cli import InjectorCLI, create_argument_parser


def main() -> int:
    parser = create_argument_parser()
    args = parser.parse_args()
    
    cli = InjectorCLI(args)
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
