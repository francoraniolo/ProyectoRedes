//Estructura Header DNS RFC 1035

struct DNS_HEADER
{
    unsigned short id; // id | 16 bits 
    
    unsigned char rd :1; // recursion desired | 1 bit
    unsigned char tc :1; // truncated message | 1 bit  
    unsigned char aa :1; // authoritive answer | 1 bit
    unsigned char opcode :4; // proposito del mensaje | 4 bits
    unsigned char qr :1; // query/response flag | 1 bit
    
    
    
    unsigned char rcode :4; // codigo respuesta | 4 bits
    unsigned char z :3; // reservado para futuros usos, debe ser cero | 1 bit
    unsigned char ra :1; // recursion available | 1 bit
    

 
    unsigned short qdcount;  // numero de entradas en seccion de preguntas | 16 bits
    unsigned short ancount;  // numero de rr en seccion de respuestas | 16 bits
    unsigned short nscount;  // numero de nameservers en la seccion de registros de autoridad | 16 bits
    unsigned short arcount;  // numero de rr en seccion de registros adicionales | 16 bits
    
};

//Estructura QUESTION RFC 1035
struct QUESTION
{
    unsigned short qtype; //tipo de query
    unsigned short qclass; //clase de query, va IN para internet
};

#pragma pack(push, 1)

//Estructura Resource Data

struct RDATA
{
    //ESTANDAR RDATA
    unsigned short type;
    unsigned short class;
    unsigned int ttl ;
    unsigned short datalen ;

};

#pragma pack(pop)

//Estructura Resource Record

struct RESRECORD
{
    unsigned char *name;
//  unsigned short type;
    struct RDATA *resource;
    unsigned char *rdata;
};

//Estructura de Query

typedef struct
{
    unsigned char *name;   //qname
    struct QUESTION *ques;
} CONSULTA;