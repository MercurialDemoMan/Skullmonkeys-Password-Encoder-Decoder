Skullmonkeys passwords

Symbols (values represent byte)

	Empty space = 0x00
	Cross       = 0x00 (note: cross is not equivalent to empty space! Password length also takes place in password verifaction)
	Square      = 0x01
	Triangle    = 0x02
	Circle      = 0x03
	L1          = 0x04
	L2          = 0x05
	R1          = 0x06
	R2          = 0x07

Saved items:

	Lives:   0 - 99
	Pharts:  0 - 7
	Birds:   0 - 7
	Willies: 0 - 7
	Enema:   0 - 7
	1870s:   0 - 3
	Level:   1 - 31 (note: there are only 25 real levels, levels between 26 and 31 are treated as Skullmonkeys Gate level)
	Password seed: 0 - 48 (note: extra value to make password with same data different)

PSX RAM Layout:

	Password buffer: 0x8009CB5C (12 bytes)
	Password length: 0x800A609D (1 byte)

	Password encoding subroutine: 0x80025C78
	Password decoding subroutine: 0x80025E44

	Password data lookup table: 0x8009B1F4

Password:

	Consists of password buffer and password length.

	Last symbol of a password is checksum and is calculated by adding previous symbols together and then taking the first 3 low significant bits.

	Each symbol excluding the check sum represents data.
	Each bit set to 1 in the symbol represents data modification.
	Data modification is managed through lookup table.
	Lookup table is 64 bytes long and contains pairs consisting of [data index, data modification]
	Index into the lookup table for a pair is the bit index which is being currently processed and set to 1
	It will then OR the data with the value from the lookup table.
