#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

/**
 * \brief data index
 */
typedef enum
{
    level   = 0,
    lives   = 1,
    birds   = 2,
    pharts  = 3,
    enemas  = 4,
    willies = 5,
    _1970s  = 6,
    seed    = 7
} data_t;

/**
 * \brief valid password symbols
 */
typedef enum
{
    cr = 0,
    sq = 1,
    tr = 2,
    ci = 3,
    l1 = 4,
    l2 = 5,
    r1 = 6,
    r2 = 7
} symbols_t;

/**
 * \brief password accumulator lookup table
 * \note extracted from psx memory at 0x8009B1F4 
 */
static u8 pwd_data_lookup_table[] = 
{
    0x01, 0x00, 
    0x01, 0x01,
    0x01, 0x02, 
    0x01, 0x03,
    0x00, 0x00, 
    0x07, 0x00,
    0x00, 0x01, 
    0x07, 0x01,
    0x01, 0x04, 
    0x06, 0x00,
    0x00, 0x02,
    0x07, 0x02,
    0x02, 0x00, 
    0x03, 0x00,
    0x04, 0x00, 
    0x05, 0x00,
    0x01, 0x05, 
    0x07, 0x03,
    0x00, 0x03, 
    0x02, 0x01,
    0x03, 0x01, 
    0x04, 0x01,
    0x05, 0x01, 
    0x06, 0x01,
    0x07, 0x04, 
    0x01, 0x06,
    0x00, 0x04, 
    0x07, 0x05,
    0x02, 0x02, 
    0x03, 0x02,
    0x04, 0x02, 
    0x05, 0x02
};

/**
 * \brief sequential data names
 */
static char* data_names[] = 
{
    "Level",
    "Lives",
    "Birds",
    "Pharts",
    "Enemas",
    "Willies",
    "1970's",
    "Seed",
};

/**
 * \brief sequential level names
 */
static char* level_names[] = 
{
    "Level: Skullmonkeys Gate",
    "Level: Science Center",
    "Movie: Beans + Level: Monkey Shrines",
    "Level: The Incredible Drivy Finn",
    "Boss: Shriney Guard",

    "Level: Hard Boiler",
    "Movie: Root + Level: Sno",
    "Level: SkullMonkeys Brand HotDogs",
    "Boss: Joe-Head-Joe",

    "Level: Elevated Structure of Terror",
    "Movie: Victoid + Level: Ynt Death Garden",
    "Level: Ynt Mines", 
    "Level: Ynt Weeds",
    "Movie: Ynt + Level: Ynt Eggs",
    "Boss: Glenn Yntis",

    "Level: Monk Rushmore",
    "Level: 1970's",
    "Level: Soar Head",
    "Level: Shards",
    "Movie: Hamster + Level: Castle De Los Muertos",
    "Boss: Monkey Mage",

    "Level: The Incredible Drivy Runn",
    "Level: Worm Graveyard",
    "Boss: Klogg",

    "Movie: Evil Engine #9 + Level: Evil Engine #9",
};

/**
 * \brief sequential symbol names
 */
static char* symbol_names[] = 
{
    "Cross",
    "Square",
    "Triangle",
    "Circle",
    "L1",
    "L2",
    "R1",
    "R2"
};

/**
 * \brief decode password
 * \arg pwd_buffer - pointer to array of 12 bytes
 * \arg pwd_length - password length
 */
u8 decode_password(u8* pwd_buffer, u8 pwd_length, u8* data_buffer)
{
    //check password length
    if(pwd_length == 0) { printf("Error: password length cannot be zero\n"); return 0; }

    //calculate checksum
    u8 sum = 0;

    //add all symbols together EXCLUDING the last symbol
    //and then take 3 least significant bits from the sum
    if(pwd_length != 1)
    {
        for(u32 i = 0; i < pwd_length - 1; i++)
        {
            sum += pwd_buffer[i];
        }
    }
    sum = sum & 0b00000111;

    //last symbol in the password is the checksum
    u8 last = pwd_buffer[pwd_length - 1];

    //reject non maching sums
    if(sum != last) 
    { 
        printf("Error: checksum is not correct [sum: %s] != [last symbol: %s]\n", symbol_names[sum], symbol_names[last]); 
        return 0; 
    }

    //zero out the password reminder INCLUDING the checksum symbol
    for(u32 i = pwd_length - 1; i < 12; i++)
    {
        pwd_buffer[i] = 0;
    }

    //zero out the data
    memset(data_buffer, 0, 8);

    //decode data from password using accumulator lookup table
    //this shit is kinda complicated
    //for each password symbol it will iterate through the first 3 least significant bits
    //(note: it should iterate through 33 bits because 11 valid symbols * 3 bits = 33, but the game ignores
    //       the last bit of the last valid symbol, so for example passwords:
    //           R2 L1 R1 L2 L1 R1 R2 L2 L1 R2 R1 L2
    //           R2 L1 R1 L2 L1 R1 R2 L2 L1 R2 Triangle Square
    //       are equivalent)
    //for each bit that is 1, based on lookup table, choose which data will be modified and how it will be modified
    u32 idx     = 0; // <- symbol index
    u32 shifter = 0; // <- symbol bit index

    //for every three bits of every valid symbol
    for(u32 i = 0; i < 32; i++)
    {
        //check if bit is set
        if(((pwd_buffer[idx] >> shifter) & 1) == 1) 
        {
            u8 t1 = data_buffer[pwd_data_lookup_table[(i * 2) + 0]]; // <- choose data to modify based on bit index
            u8 t2 =        1 << pwd_data_lookup_table[(i * 2) + 1];  // <- choose how the data will be modified

            //modify data
            data_buffer[pwd_data_lookup_table[i * 2]] = t1 | t2;
        }

        //if we processed three bits, move onto the next symbol
        if(++shifter >= 3)
        {
            shifter = 0;
            idx++;
        }
    }

    //check data bounds
    if(data_buffer[level] > 31)  { printf("Error: level out of bounds\n");   return 0; }
    if(data_buffer[lives] > 99)  { printf("Error: lives out of bounds\n");   return 0; }
    if(data_buffer[birds] > 7)   { printf("Error: birds out of bounds\n");   return 0; }
    if(data_buffer[pharts] > 7)  { printf("Error: pharts out of bounds\n");  return 0; }
    if(data_buffer[enemas] > 7)  { printf("Error: enemas out of bounds\n");  return 0; }
    if(data_buffer[willies] > 7) { printf("Error: willies out of bounds\n"); return 0; }
    if(data_buffer[_1970s] > 3)  { printf("Error: 1970s out of bounds\n");   return 0; }
    if(data_buffer[seed] > 48)   { printf("Error: seed out of bounds\n");    return 0; }

    //check if we can have certain things
    if(data_buffer[level] < 0xD)
    {
        if(data_buffer[willies] != 0) { printf("Error: Cannot have willies before Ynt Weeds\n"); return 0; }
    }
    if(data_buffer[level] < 0xA)
    {
        if(data_buffer[enemas] != 0) { printf("Error: Cannot have enemas before Elevated Structure of Terror\n"); return 0; }
    }
    if(data_buffer[level] < 0x3)
    {
        if(data_buffer[pharts] != 0) { printf("Error: Cannot have pharts before Monkey Shrines\n"); return 0; }
        if(data_buffer[birds] != 0)  { printf("Error: Cannot have birds before Monkey Shrines\n"); return 0; }
    }

    //return level code
    return data_buffer[level];
}

/**
 * \brief encode password
 * \arg data - pointer to array of 8 bytes
 * \arg pwd_buffer - pointer to array of 12 bytes so we can set it
 * \arg pwd_length - pointer to password length so we can set it
 */
u8 encode_password(u8* data, u8* pwd_buffer, u8* pwd_length)
{
    //check if we can have certain things
    //if you comment this, the game will not accept the password
    if(data[level] < 0xD)
    {
        //check willies
        if(data[willies] != 0) { printf("Error: Cannot have willies before Ynt Weeds\n"); return 0; }
    }
    if(data[level] < 0xA)
    {
        //check enemas
        if(data[enemas] != 0) { printf("Error: Cannot have enemas before Elevated Structure of Terror\n"); return 0; }
    }
    if(data[level] < 0x3)
    {
        //check pharts
        if(data[pharts] != 0) { printf("Error: Cannot have pharts before Monkey Shrines\n"); return 0; }
        //check birds
        if(data[birds] != 0)  { printf("Error: Cannot have birds before Monkey Shrines\n"); return 0; }
    }

    //check bounds
    //if you comment this, the game will not accept the password
    if(data[level] > 31)  { printf("Error: level out of bounds\n");   return 0; }
    if(data[lives] > 99)  { printf("Error: lives out of bounds\n");   return 0; }
    if(data[birds] > 7)   { printf("Error: birds out of bounds\n");   return 0; }
    if(data[pharts] > 7)  { printf("Error: pharts out of bounds\n");  return 0; }
    if(data[enemas] > 7)  { printf("Error: enemas out of bounds\n");  return 0; }
    if(data[willies] > 7) { printf("Error: willies out of bounds\n"); return 0; }
    if(data[_1970s] > 3)  { printf("Error: 1970s out of bounds\n");   return 0; }
    if(data[seed] > 48)   { printf("Error: seed out of bounds\n");    return 0; }

    //zero out password buffer
    memset(pwd_buffer, 0, 12);

    //main encoding loop
    //same what is going on in decode_password but in revere
    u8 counter1 = 0;
    u8 counter2 = 0;

    for(u32 i = 0; i < 32; i++)
    {
        u8 t1 = pwd_data_lookup_table[i * 2];
        u8 t2 = pwd_data_lookup_table[(i * 2) + 1];

        u8 v0 = data[t1] >> t2;

        if((v0 & 1) != 0)
        {
            pwd_buffer[counter1] = pwd_buffer[counter1] | (1 << counter2);
        }

        if(++counter2 >= 3)
        {
            counter2 = 0;
            counter1++;
        }
    }

    //calculate sum of the password
    u8 sum = 0;
    //add all symbols together and then take 3 least significant bits from the sum
    for(u32 i = 0; i < 12; i++)
    {
        sum += pwd_buffer[i];
    }
    sum = sum & 0b00000111;

    //calculate checksum symbol index
    u8 last_symbol = 11;
    for(u32 i = 11; i-- > 0; )
    {
        if(pwd_buffer[i] != 0)
        {
            break;
        }

        last_symbol = i;
    }

    //write the check sum
    pwd_buffer[last_symbol] = sum;

    //write the password length
    *pwd_length = last_symbol + 1;

    return 1;
}

/**
 * \brief print help
 */
void print_help()
{
    printf("Usage: ./skullcrack -d/e [password/data]\n"
           "    -d = decode password\n"
           "    -e = encode data\n"
           "    password = 1 - 12 symbols [cr, sq, tr, ci, l1, l2, r1, r2]\n"
           "    data = level[1 - 31] (note: real levels are only to 25 - levels above 25 are treated as Skullmonkeys Gate\n"
           "                                meaning that items cannot be brought into the level even though they are encoded)\n"
           "           lives[0 - 99]\n"
           "           birds[0 - 7] (note: must be zero until level 3)\n"
           "           pharts[0 - 7] (note: must be zero until level 3)\n"
           "           enemas[0 - 7] (note: must be zero until level 10)\n"
           "           willies[0 - 7] (note: must be zero until level 13)\n"
           "           1970s[0 - 3]\n"
           "           { optional: password seed[0 - 48] }\n\n"
           "Example 1: ./skullcrack -e 3 95 0 0 0 0 0 -> R2, Circle, L2, Cross, Cross, Cross, Cross, Cross, Triangle, Square \n\n"
           "Example 2: ./skullcrack -d sq tr ci -> Level: Skullmonkeys Gate, Lives: 1, Birds: 0, ... \n\n"
           "Levels: \n");

    for(u32 i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++)
    {
        printf("%i - %s\n", i + 1, level_names[i]);
    }
}

/**
 * \brief main program
 */
int main(int argc, char* argv[])
{
    //check arguments
    if(argc < 2)
    {
        print_help();
        return 0;
    }
    else
    {
        #define strequ(s1, s2) !strcmp(s1, s2)

        //start decoding
        if(strequ(argv[1], "-d"))
        {
            if(argc < 3 || argc > 14)
            {
                printf("Error: password must have 1 - 12 symbols\n");
                return 0;
            }
            else
            {
                //create password buffer
                u8 pwd_buffer[12] = { [0 ... 11] = 0 };

                //parse input
                for(u32 i = 2; i < argc; i++)
                {
                    if(strequ(argv[i], "cr")) { pwd_buffer[i - 2] = cr; } else
                    if(strequ(argv[i], "sq")) { pwd_buffer[i - 2] = sq; } else
                    if(strequ(argv[i], "tr")) { pwd_buffer[i - 2] = tr; } else
                    if(strequ(argv[i], "ci")) { pwd_buffer[i - 2] = ci; } else
                    if(strequ(argv[i], "l1")) { pwd_buffer[i - 2] = l1; } else
                    if(strequ(argv[i], "l2")) { pwd_buffer[i - 2] = l2; } else
                    if(strequ(argv[i], "r1")) { pwd_buffer[i - 2] = r1; } else
                    if(strequ(argv[i], "r2")) { pwd_buffer[i - 2] = r2; } else
                    { 
                        printf("Error: password contains invalid symbol\n"); 
                        printf("Note: valid symbols: cr, sq, tr, ci, l1, l2, r1, r2\n");
                        return 0;
                    }
                }

                //create data buffer
                u8 data_buffer[8] = { [0 ... 7] = 0 };

                //decode password
                u8 res = decode_password(&pwd_buffer[0], argc - 2, &data_buffer[0]);

                //print result
                if(res)
                {
                    printf("Valid password\nLevel: %u\nLives: %u\nBirds: %u\nPharts: %u\nEnemas: %u\nWillies: %u\n1970s: %u\nSeed: %u\n",
                        data_buffer[level], data_buffer[lives], data_buffer[birds], data_buffer[pharts], data_buffer[enemas], data_buffer[willies], data_buffer[_1970s], data_buffer[seed]);
                }
                else
                {
                    printf("Invalid password\n");
                }
            }
        }
        //start encoding
        else if(strequ(argv[1], "-e"))
        {
            if(argc != 9 && argc != 10)
            {
                printf("Error: invalid number of items\n");
                return 0;
            }
            else
            {
                //create data buffer
                u8 data_buffer[8] = { [0 ... 7] = 0 };

                //parse input
                u32 input_buffer;
                for(u32 i = 2; i < argc; i++)
                {
                    if(sscanf(argv[i], "%u", &input_buffer) != 1) 
                    { 
                        printf("Error: data contain invalid characters\n"); 
                        printf("Note: just use numbers\n");
                        return 0; 
                    }

                    data_buffer[i - 2] = (u8)input_buffer;
                }

                //create password buffer
                u8 pwd_buffer[12] = { [0 ... 7] = 0 };
                u8 pwd_length     = 0; 

                //encode password into password buffer
                u8 res = encode_password(&data_buffer[0], &pwd_buffer[0], &pwd_length);

                //print result
                if(res)
                {
                    printf("Encoding successfull\n");
                    //print result
                    for(u32 i = 0; i < pwd_length; i++)
                    {
                        printf("%s\n", symbol_names[pwd_buffer[i]]);
                    }
                }
                else
                {
                    printf("Encoding failed\n");
                }
            }
        }
        //help
        else if(strequ(argv[1], "-h"))
        {
            print_help();
        }
        else if(strequ(argv[1], "--help"))
        {
            print_help();
        }
        //invalid command
        else
        {
            printf("Error: First argument must be \"-c\" or \"-e\"");
        }

        #undef strequ
    }

    return 0;
}















