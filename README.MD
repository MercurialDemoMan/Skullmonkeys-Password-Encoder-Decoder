Skullmonkeys passwords

Symbols (values represent byte)
	Empty space = 0x00
	Cross       = 0x00 (note: cross is not equivalent with empty space! Password length also takes place in password verifaction)
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

PSX RAM Layout:
	Password buffer: 0x8009CB5C (12 bytes)
	Password length: 0x800A609D (1 byte)

	Password encoding subroutine: 0x80025C78
	Password decoding subroutine: 0x80025E44

	Password data lookup table: 0x8009B1F4

Everything else is in the source
