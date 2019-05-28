#include <stdio.h> //printf
#include <string.h> //memset()
#include <stdlib.h> //malloc, atoi()
#include <sys/socket.h> //socket(), connect(), send(), recv()
#include <arpa/inet.h> //inet_addr, etc.
#include <netinet/in.h>
#include <unistd.h> //getpid, close()

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
    //  unsigned char cd :1; // checking disabled, preguntar si va
    //  unsigned char ad :1; // authenticated data, preguntar si va
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
} QUERY;

//Declaraciones de funciones
void ngethostbyname(unsigned char *host , int query_type);

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);

void get_dns_servers();

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);

void validarConsulta(int argc, char *argv[]);

void eliminarArrobaDeString(char* p);

void append(char* s, char c);

void guardarPuerto(char* p);

//Variables Globales necesarias
unsigned char hostname[100];
unsigned char dns_server[100];
char puerto[20]="";
int preferencia[20];
/*
 * 
 * 
 * 
 */


int main( int argc , char *argv[]){
    
    //unsigned char hostname[100];


    //Get the DNS servers from the resolv.conf file
    //get_dns_servers(); despues lo veo
     
    //Get the hostname from the terminal
    
    //Revisamos cantidad de argumentos

    if (argc>7 || argc<2){
        printf("Error: Cantidad inválida de argumentos \n");
        exit(EXIT_FAILURE); 
    }
    
    validarConsulta(argc,argv);

    printf("Su servidor dns es %s\n",dns_server);    
    
    //Now get the ip of this hostname , A record
    //ngethostbyname(hostname , 1);
    ngethostbyname(hostname , 15); //MX record
    return 0;
}

/*
 * 
 * Realiza una consulta DNS enviando un paquete
 * */

void ngethostbyname(unsigned char *host , int query_type){

 unsigned char buf[65536],*qname,*reader;
 
 int i , j , stop , s;
 
 struct sockaddr_in a;

 struct RESRECORD answers[20],auth[20],addit[20]; //respuestas del servidor DNS

 struct sockaddr_in dest;

 struct DNS_HEADER *dns = NULL;
 struct QUESTION *qinfo = NULL;

 printf("Resolviendo %s" , host);
 
 s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //Paquete UDP para consultas dns

 dest.sin_family = AF_INET;  //Siempre va AF_INET
 dest.sin_port = htons((short)53);  //Paso numero de puerto de manera que se pueda entender en bits
 dest.sin_addr.s_addr =inet_addr(dns_server); //inet_addr("8.8.8.8");//inet_addr(dns_servers[0]); inet_addr("127.0.0.1")  dentro de la funcion va el ip del servidor dns en string

  //Seteamos la estructura DNS a las consultas estandar
 dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short) htons(getpid()); 
    dns->qr = 0; //0 porque es consulta
    dns->opcode = 0; //consulta estandar
    dns->aa = 0; //No autoritativa
    dns->tc = 0; //Mensaje no truncado
    dns->rd = 1; //Recursion deseada
    dns->ra = 0; //Recursion no disponible
    dns->z = 0; 
    dns->rcode = 0;
    dns->qdcount = htons(1); //tenemos solo 1 pregunta
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    //apunta a la porcion de consulta
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    
    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
 
    printf("\nEnviando Paquete...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Listo.");

    //Receive the answer
    i = sizeof dest;
    printf("\nRecibiendo respuesta...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Listo.");
 
    dns = (struct DNS_HEADER*) buf;

    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nLa respuesta contiene : ");
    printf("\n %d Preguntas.",ntohs(dns->qdcount));
    printf("\n %d Respuestas.",ntohs(dns->ancount));
    printf("\n %d Servidores Autoritativos.",ntohs(dns->nscount));
    printf("\n %d Registros adicionales.\n\n",ntohs(dns->arcount));

    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(dns->ancount);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct RDATA*)(reader);
        reader = reader + sizeof(struct RDATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->datalen));
 
            for(j=0 ; j<ntohs(answers[i].resource->datalen) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->datalen)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->datalen);
        }
        else
        {
            if(ntohs(answers[i].resource->type) == 15) 
            {
            //Leo campo preferencia                 
            preferencia[i]=(int) reader[1];
            //Leo campo Exchange
            answers[i].rdata = ReadName(reader+2,buf,&stop);
            reader = reader + stop + 2;
                
            }
            else{
                answers[i].rdata = ReadName(reader,buf,&stop);
                reader = reader + stop;
            }
        }
    }

    //read authorities
    for(i=0;i<ntohs(dns->nscount);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct RDATA*)(reader);
        reader+=sizeof(struct RDATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(dns->arcount);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct RDATA*)(reader);
        reader+=sizeof(struct RDATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->datalen));
            for(j=0;j<ntohs(addit[i].resource->datalen);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->datalen)]='\0';
            reader+=ntohs(addit[i].resource->datalen);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }

    //print answers
    printf("\nRegistros de respuestas : %d \n" , ntohs(dns->ancount) );
    for(i=0 ; i < ntohs(dns->ancount) ; i++)
    {
        printf("Nombre : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            printf("tiene la direccion IPv4 : %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            printf("tiene un nombre de alias : %s",answers[i].rdata);
        }
        else
        {
            
            if(ntohs(answers[i].resource->type)==15){
                
                printf("Preferencia: %d  ",preferencia[i]);
                printf("Exchange: %s",answers[i].rdata);
                
            } 
            
            

        }
        


        printf("\n");
    }

    //print authorities
    printf("\nRegistros de Autoridad : %d \n" , ntohs(dns->nscount) );
    for( i=0 ; i < ntohs(dns->nscount) ; i++)
    {
         
        printf("Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            printf("tiene nameserver : %s",auth[i].rdata);
        }
        printf("\n");
    }

    //print additional resource records
    printf("\nRegistros Adicionales : %d \n" , ntohs(dns->arcount) );
    for(i=0; i < ntohs(dns->arcount) ; i++)
    {
        printf("Nombre : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("tiene la direccion IPv4 : %s",inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }

   return;
}

 unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{

    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers()
{

    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Failed opening /etc/resolv.conf file \n");
    }
     
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
             
            //p now is the dns ip :)
            //????
        }
    }
     
  //  strcpy(dns_servers[0] , "208.67.222.222");
  //  strcpy(dns_servers[1] , "208.67.220.220");
}

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void validarConsulta(int argc,char *argv[])
{
    int i=0;
    int consulta,servidor,amxloc,rt,h;
    char srv[20]=""; 
    char arroba;

 for(i=1;i<argc;i++){
    
    if(strcmp(argv[i],"-h")==0)
        {
            if(h==1) {
                printf("Parámetro -h repetido \n");
                exit(EXIT_FAILURE);   
                  }
            h=1;
        }
    else{  
    if(strcmp(argv[i],"-a")==0)
        {
            if(amxloc==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                       }
            amxloc=1;     
        }
    else{    
    if(strcmp(argv[i],"-mx")==0)
    {
            if(amxloc==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            amxloc=1;     
    }       
    else{ 
    if(strcmp(argv[i],"-loc")==0)
    {
            if(amxloc==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            amxloc=1;     
    }
    else{
    if(strcmp(argv[i],"-r")==0)
    {
            if(rt==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            rt=1;     
    }        
    else{
    if(strcmp(argv[i],"-t")==0)
    {        
            if(rt==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            rt=1;     
    }
    else{
        
        if('@'==argv[i][0])   //Si esto pasa es el servidor!
          { 
           if(servidor==1)
                {
                    printf("Ingrese un único servidor por favor.\n");
                    exit(EXIT_FAILURE);
                }
            servidor=1;
            strcpy(dns_server,argv[i]);
            eliminarArrobaDeString(dns_server);
            
          }
        else{       //Si llegué acá es una consulta!
            if(consulta==1)
             {
                 printf("Ingrese una única consulta por favor.\n");
                 exit(EXIT_FAILURE);
             }
            strcpy(hostname,argv[i]);
            consulta=1;
        }  
        }
        }}}}}          
  }//termina el for

   if(consulta==0 && h==0){   //No hay consulta y no pidió ayuda
            printf("Comando inválido. No hay consulta.\n");
            exit(EXIT_FAILURE);
        }
        else
        {
         if(h==1){
             printf("Ayuda \n"); //Imprimir ayuda
             exit(EXIT_FAILURE); // Y termino el programa
         }   
        }

  
}

void eliminarArrobaDeString(char* p)
{
   int yaElimineArroba=0; //Variable para no borrar más arrobas en caso de que las haya
                          //(El usuario siempre es impredecible)
   char c='@';
   int voyPorPuerto=0;   //En caso de que ya este por el puerto -> no registrarlo en servidor  
    if(NULL==p)
        return;
    char* pDest = p; //Mismo que p (Apunta al principio del string)

    while(*p)           //Saco el arroba
    {
     if(*p!=':' && voyPorPuerto==0){   //Si no voy por puerto -> anoto servidor a no ser que sea @
        if(*p != c || yaElimineArroba==1)
            *pDest++=*p;
        else{
          yaElimineArroba=1;  
        }
        
    }
    else{                              //Estamos en puerto! -> Registremos el numero luego del ':'
       if(voyPorPuerto==0) 
        voyPorPuerto=1;
        else
        {
            
         append(puerto,*p);       //Concatenamos uno de los numeros del puerto
          
        }
        
    }
     p++;
    } 
    *pDest='\0';

    printf("El puerto es %s\n",puerto);
}


void append(char* s, char c)
{
        int len = strlen(s);
        s[len] = c;
        s[len+1] = '\0';
}
 
