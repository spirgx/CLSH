//---------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
//---------------------------------------------------------------------------

#define BUFFER_SIZE     4096
#define PATH_LENGTH     1024
#define SHA1_LENGTH       40
#define ENC_STRING      "_ENC"
#define DEC_STRING      "_DEC"

#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

typedef enum {ENC , DEC} ENC_DEC;

typedef struct SHA1Context
{
    unsigned Message_Digest[5]; /* Message Digest (output)          */

    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */

    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
} SHA1Context;

void Usage(const char*);
void ListAllFile(ENC_DEC,char*,char*,bool);
void GetFileSHA1Code(const char*, char*);
void Encryption(const char* , const char*, const bool);
void Decryption(const char* , const char*, const bool);

void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *, const unsigned char *, unsigned);
void SHA1ProcessMessageBlock(SHA1Context *);
void SHA1PadMessage(SHA1Context *);

int main(int argc, char *argv[])
{
    int index = 0;
    ENC_DEC CodeType;
    char InputPath[PATH_LENGTH];
    char OutputPath[PATH_LENGTH]="";
    bool TheSameDir=true;

    clock_t start_time, end_time;

    start_time = clock();

    if (argc == 1 || (argc > 1 && (!strncmp(argv[1],"-?",2) || !strncmp(argv[1],"-help",5))))
    {
        Usage(argv[0]);
        return 1;
    }

    for(index= 1; index < argc; index++)
    {
        if( strlen(argv[index]) == 2 && (!strncmp(argv[index], "-E", 2) || !strncmp(argv[index], "-e", 2) ||
                                         !strncmp(argv[index], "-D", 2) || !strncmp(argv[index], "-d", 2) ||
                                         !strncmp(argv[index], "-O", 2) || !strncmp(argv[index], "-o", 2)))
        {
            ;
        }
        else
        {
            printf("[MAIN] Parameter error。\n\n");
            Usage(argv[0]);
            return 1;
        }

        switch( *(argv[index] + 1) )
        {
            case 'E':
            case 'e':   //加密
                CodeType = ENC;
                index++;
                strncpy(InputPath, argv[index], PATH_LENGTH);
                break;
            case 'D':
            case 'd':   //解密
                CodeType = DEC;
                index++;
                strncpy(InputPath, argv[index], PATH_LENGTH);
                break;
            case 'O':
            case 'o':   //輸出目錄
                index++;
                strncpy(OutputPath, argv[index], PATH_LENGTH);
                TheSameDir = false;
                break;
            default:
                printf("[MAIN] Parameter error。\n");
                Usage(argv[0]);
                return 1;
        }
    }

    if(TheSameDir)
        strncpy(OutputPath, InputPath, PATH_LENGTH);

    ListAllFile(CodeType,InputPath,OutputPath,TheSameDir);

    end_time = clock();

    printf("[Time] %.3f sec \n",(float) (end_time - start_time)/CLOCKS_PER_SEC);

    return 0;
}

void GetFileSHA1Code(const char* InputFilePath, char* SHA1Code)
{
    unsigned char c;
    SHA1Context sha;
    FILE *InputFile = fopen(InputFilePath, "rb");

    if(!InputFile)
    {
        printf("[SHA-1] %s Input file failed。\n", InputFilePath);
        return ;
    }

    SHA1Reset(&sha);

    c = fgetc(InputFile);
    while(!feof(InputFile))
    {
        SHA1Input(&sha, &c, 1);
        c = fgetc(InputFile);
    }

    fclose(InputFile);

    if (!SHA1Result(&sha))
    {
        printf("[SHA-1] file：%s SHA-1 Code failed\n", InputFilePath);
    }
    else
    {
        sprintf( SHA1Code,
                 "%08X%08X%08X%08X%08X",
                 sha.Message_Digest[0],
                 sha.Message_Digest[1],
                 sha.Message_Digest[2],
                 sha.Message_Digest[3],
                 sha.Message_Digest[4] );
    }
    printf("[SHA-1] %s - %s\n", SHA1Code, InputFilePath);
    return ;
}

void Decryption(const char* InputFilePath, const char* OutputFilePath, const bool TheSameDir)
{
    int index, ret;
    long size;
    char SHA1Code[41];
    char SHA1Check[41];
    char* Data = (char*)malloc(sizeof(char) * BUFFER_SIZE);
    char TempPath[PATH_LENGTH];

    FILE* InputFile = fopen(InputFilePath, "rb");
    FILE* OutputFile = fopen(OutputFilePath, "wb");

    if (!InputFile)
    {
        printf("[DEC] %s Input file failed。\n", InputFilePath);
        return ;
    }

    if (!OutputFile)
    {
        printf("[DEC] %s Output file failed。\n", OutputFilePath);
        return ;
    }

    fseek(InputFile, 0, SEEK_END);
    size = ftell(InputFile);
    fseek(InputFile, 0, SEEK_SET);
    size = size - SHA1_LENGTH;

    while((size -= BUFFER_SIZE) > 0)
    {
        ret = fread(Data, 1, BUFFER_SIZE, InputFile);
        for(index = 0; index < ret; index++)
            Data[index] = ~Data[index];
        fwrite(Data, 1, ret, OutputFile);
    }

    ret = fread(Data, 1, BUFFER_SIZE + size, InputFile);
    for(index = 0; index < ret; index++)
        Data[index] = ~Data[index];
    fwrite(Data, 1, ret, OutputFile);
    fclose(OutputFile);

    ret = fread(Data, 1, SHA1_LENGTH, InputFile);
    strncpy(SHA1Code, Data,SHA1_LENGTH);
    SHA1Code[40] = '\0';
    fclose(InputFile);

    GetFileSHA1Code(OutputFilePath, SHA1Check);
    if(!strncmp(SHA1Code, SHA1Check, SHA1_LENGTH))
    {
        printf("[File] %s is right file.\n", InputFilePath);
        if(TheSameDir)
        {
            remove(InputFilePath);
            rename(OutputFilePath, InputFilePath);
        }
        else
        {
            //remove(InputFilePath);
            strncpy(TempPath, OutputFilePath,PATH_LENGTH);
            TempPath[strlen(TempPath)-4] = '\0';
            rename(OutputFilePath, TempPath);
        }
    }
    else
        printf("[File] %s is error file.\n", InputFilePath);

    return ;
}

void Encryption(const char* InputFilePath, const char* OutputFilePath, const bool TheSameDir)
{

    int index, ret;
    char SHA1Code[41];
    char* Data = (char*)malloc(sizeof(char) * BUFFER_SIZE);
    char TempPath[PATH_LENGTH];

    FILE* InputFile = fopen(InputFilePath, "rb");
    FILE* OutputFile = fopen(OutputFilePath, "wb");

    if (!InputFile)
    {
        printf("[ENC] %s Input file failed。\n", InputFilePath);
        return ;
    }

    if (!OutputFile)
    {
        printf("[ENC] %s Output file failed。\n", OutputFilePath);
        return ;
    }

    ret = fread(Data, 1, BUFFER_SIZE, InputFile);
    while( ret > 0)
    {
        for(index = 0; index < ret; index++)
            Data[index] = ~Data[index];
        fwrite(Data, 1, ret, OutputFile);
        ret = fread(Data, 1, BUFFER_SIZE, InputFile);
    }

    GetFileSHA1Code(InputFilePath, SHA1Code);
    fwrite(SHA1Code,1, SHA1_LENGTH, OutputFile);

    fclose(InputFile);
    fclose(OutputFile);

    if(TheSameDir)
    {
        remove(InputFilePath);
        rename(OutputFilePath, InputFilePath);
    }
    else
    {
        //remove(InputFilePath);
        strncpy(TempPath, OutputFilePath,PATH_LENGTH);
        TempPath[strlen(TempPath)-4] = '\0';
        rename(OutputFilePath, TempPath);
    }

    return ;
}

void ListAllFile(ENC_DEC CodeType, char *InputPath, char *OutputPathT, bool TheSameDir)
{
    char glue='\\'; // Windows 的分隔符號
    char OutputPath[PATH_LENGTH];
    struct dirent *filename;
    int pathLength, i;
    char *pathStr, *outPathStr;

    if(TheSameDir)
        strncpy(OutputPath, InputPath, PATH_LENGTH);
    else
        strncpy(OutputPath, OutputPathT, PATH_LENGTH);

    // 嘗試開啟目錄
    DIR * dp = opendir(InputPath);

    if (!dp)
    {
        // 不是目錄而是檔案，進行Complement運算
        if(CodeType == ENC)
        {
            Encryption(InputPath, strcat(OutputPath, ENC_STRING), TheSameDir);
            return ;
        }
        else if(CodeType == DEC)
        {
            Decryption(InputPath, strcat(OutputPath, DEC_STRING), TheSameDir);
            return ;
        }
        else
        {
            printf("Error END_DEC type.");
            return ;
        }
    }


    while((filename=readdir(dp)))
    {
        // 跳過當前及母目錄
        if(!strcmp(filename->d_name,"..") || !strcmp(filename->d_name,"."))
            continue;

        // 計算新的路徑字串所需的長度
        pathLength=strlen(InputPath)+strlen(filename->d_name)+2;
        // 產生新的陣列空間
        pathStr = (char*)malloc(sizeof(char) * pathLength);
        // 複製當前目錄路徑至新的陣列空間
        strcpy(pathStr, InputPath);

        pathLength=strlen(OutputPath)+strlen(filename->d_name)+2;
        // 產生新的陣列空間
        outPathStr = (char*)malloc(sizeof(char) * pathLength);
        // 複製當前目錄路徑至新的陣列空間
        strcpy(outPathStr, OutputPath);
        mkdir(outPathStr);

        // 檢查目錄分隔符號
        i=strlen(pathStr);
        if(pathStr[i-1]!=glue)
        {
            pathStr[i]=glue;
            pathStr[i+1]='\0';
        }

        i=strlen(outPathStr);
        if(outPathStr[i-1]!=glue)
        {
            outPathStr[i]=glue;
            outPathStr[i+1]='\0';
        }

        // 串接次目錄名稱或檔案名稱至新的陣列空間
        strncat(pathStr, filename->d_name,PATH_LENGTH);
        strncat(outPathStr, filename->d_name,PATH_LENGTH);

        // 遞迴呼叫目錄掃瞄
        ListAllFile(CodeType, pathStr, outPathStr, TheSameDir);
    }

    // 關閉目錄
    closedir(dp);

    return ;
}

void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;
}

int SHA1Result(SHA1Context *context)
{

    if (context->Corrupted)
    {
        return 0;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }

    return 1;
}

void SHA1Input(     SHA1Context         *context,
                    const unsigned char *message_array,
                    unsigned            length)
{
    if (!length)
    {
        return;
    }

    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }

    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
                                                (*message_array & 0xFF);

        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            /* Force it to 32 bits */
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int         t;                  /* Loop counter                 */
    unsigned    temp;               /* Temporary word value         */
    unsigned    W[80];              /* Word sequence                */
    unsigned    A, B, C, D, E;      /* Word buffers                 */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Message_Digest[0] =
                        (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] =
                        (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] =
                        (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] =
                        (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] =
                        (context->Message_Digest[4] + E) & 0xFFFFFFFF;

    context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;

    SHA1ProcessMessageBlock(context);
}

void Usage(const char* argv0)
{
    printf("Use 1 Complement encryption or decryption file, and add SHA-1 code at end of file。\n\n");
    printf("%s [-E | -e |-D | -d] [<file path> | <directory path>] ([-O | -o] [<file path> | <directory path>])\n\n", argv0);
    printf(" -E | -e                 Encryption file\n\n");
    printf(" -D | -d                 Decryption file\n\n");
    printf(" -O | -o (Optional)      Output directory\n\n");
    printf(" -? | -help              Command description\n");
}

//---------------------------------------------------------------------------
