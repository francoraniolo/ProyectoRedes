#include <stdio.h> //printf
#include <string.h> //memset()
#include <stdlib.h> //malloc, atoi()
#include <sys/socket.h> //socket(), connect(), send(), recv()
#include <arpa/inet.h> //inet_addr, etc.
#include <netinet/in.h>
#include <unistd.h> //getpid, close()
#include "location_reader.c"

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
} CONSULTA;//QUERY;

//Declaraciones de funciones
void ngethostbyname(unsigned char *host , int query_type);

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);

void get_dns_servers();

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);

void validarConsulta(int argc, char *argv[]);

void eliminarArrobaDeString(char* p);

void append(char* s, char c);

void guardarPuerto(char* p);

void consultaTrace(unsigned char *host, int query_type);

int random_number(int min_num, int max_num);

void mostrarAyuda();

//Variables Globales necesarias
unsigned char hostname[100];
unsigned char dns_server[100];
unsigned char proximo_server[100];
unsigned char ipDisponibleEnAdicional[50];
char puerto[20]="";
unsigned short int tipoQuery = 1;
unsigned short int necesitoIpNameserver=0;


//Booleans ingresados
unsigned short int puertoIngresado = 0;         
unsigned short int iteracionIngresada = 0;

//Variables para MX
int preferencia[20];
//Variables para LOC
unsigned char *coordenadas;
//Variables para trace
int seguirTrace=0;
int EsPrimeraIteracion=1;
unsigned char * nameservers[25];
int trace=0;
int cantidadNS=0;
int noEsDeInicio=0;


/*
 * 
 * 
 * 
 */


int main( int argc , char *argv[]){
    

    //Get the DNS servers from the resolv.conf file
     
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
    //ngethostbyname(hostname , 29); //Loc record
    

    // iteracionIngresada=1; //harcodeo de trace
    if(iteracionIngresada==1){
     
    unsigned char prueba[100];
    ngethostbyname(prueba,2);   //Pedimos nameservers a Root
    
    if(cantidadNS<1){exit(EXIT_FAILURE);}
    int r = random_number(0,cantidadNS-1);
    printf("El root_nameserver aleatorio es %s \n",nameservers[r]);
    ngethostbyname(nameservers[r],1); //Pedimos ipv4 a nameserver de root aleatorio 
    printf("El proximo server es : %s\n",proximo_server);
    noEsDeInicio=1;
    seguirTrace=1;
    int contador=0;
    while(seguirTrace){
   // if(contador==5)exit(EXIT_FAILURE); //TESTING
    if(necesitoIpNameserver==0){
    ngethostbyname(hostname,tipoQuery);
    hostname[strlen(hostname)-1]='\0'; //Eliminamos el punto agregado por el metodo. 
    if(seguirTrace==1){
    printf("El proximo server es : %s\n",proximo_server);
                      }
    }
    else{                   //Necesito ip de un nameserver

                if(cantidadNS<1)
                    {
                    printf("Error: cantidad nameservers nula \n");
                    exit(EXIT_FAILURE);
                    }
                r = random_number(0,cantidadNS-1);
                printf("(necesitoipnameserver activado) El root_nameserver aleatorio es %s \n",nameservers[r]);
                ngethostbyname(nameservers[r],1); //Pedimos ipv4 a nameserver de root aleatorio 




            /*    ahora ya tengo ip, lo copio en proximo_server
                seteo necesitoIpNameserver=0;
                tengo que cuidarme que cuando haga esto, no setee el seguirTrace en cero. 
           */
           
           
           // r = random_number(0,cantidadNS-1);
           // printf("El root_nameserver aleatorio es %s \n",nameservers[r]);
           // ngethostbyname(nameservers[0],1); //Pedimos ipv4 a nameserver de root aleatorio 
           // printf("El proximo server es : %s\n",proximo_server);

        }
        contador++; //TESTING
    }
    }
    else{
     ngethostbyname(hostname,tipoQuery);   
    }

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

 printf("Resolviendo %s \n" , host);
 
 s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //Paquete UDP para consultas dns

 dest.sin_family = AF_INET;  //Siempre va AF_INET
 
 if(puertoIngresado==0) {             //Si no hay puerto, ingreso por defecto puerto 53
 dest.sin_port = htons((short)53);  //Paso numero de puerto de manera que se pueda entender en bits
  strcpy(puerto,"53");
 }
 else{
 dest.sin_port = htons((short)atoi(puerto));   //Si hay puerto, lo ingreso
 }
 printf("El puerto es %s\n",puerto);

 
     
        
     //printf("dns_server es %s \n",dns_server);
     
     //printf("proximo_server es %s \n",proximo_server);

    if(iteracionIngresada==0){
    dest.sin_addr.s_addr =inet_addr(dns_server);
    }
    else{
        if(seguirTrace==0){
            dest.sin_addr.s_addr =inet_addr(dns_server); //
        }else{
            if(necesitoIpNameserver==1){
                dest.sin_addr.s_addr =inet_addr(dns_server);
            }
            else
            {
                dest.sin_addr.s_addr =inet_addr(proximo_server);
            }
            
        }
    }       
    
 
  //Seteamos la estructura DNS a las consultas estandar
 dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short) htons(getpid()); 
    dns->qr = 0; //0 porque es consulta
    dns->opcode = 0; //consulta estandar
    dns->aa = 0; //No autoritativa
    dns->tc = 0; //Mensaje no truncado
    
    if(iteracionIngresada==0)
        {
            dns->rd = 1; //Recursion deseada
            
        }
    else
        {
            if(query_type==2)
                {
                   dns->rd = 1; //Recursion deseada
                  
                }
            else
                {
                    if(necesitoIpNameserver==1){
                        dns->rd = 1; //Recursion deseada
                        
                    }
                    else{
                        dns->rd = 0; //Recursion deseada
                    }
                }

        }   
    
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
            if(ntohs(answers[i].resource->type) == 15) //SI ES TIPO MX
            {
            //Leo campo preferencia                 
            preferencia[i]=(int) reader[1];
            //Leo campo Exchange
            answers[i].rdata = ReadName(reader+2,buf,&stop);
            reader = reader + stop + 2;
                
            }
            else{
                if (ntohs(answers[i].resource->type) == 29) //SI ES TIPO LOC
                {
                    coordenadas=(char *)loc_ntoa(reader,NULL); 
                    //reader = reader + stop;
                }
                else
                {
                    if(ntohs(answers[i].resource->type) == 2) //SI ES TIPO NS
                    {   
                        answers[i].rdata = ReadName(reader,buf,&stop);
                        reader = reader + stop;
                    }
                    else{              
                         answers[i].rdata = ReadName(reader,buf,&stop);
                         reader = reader + stop;
                    }
                }
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
            if(ntohs(addit[i].resource->type)==2){ //TIPO NS
                addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->datalen));
                for(j=0;j<ntohs(addit[i].resource->datalen);j++)
                addit[i].rdata[j]=reader[j];
 
                addit[i].rdata[ntohs(addit[i].resource->datalen)]='\0';
                reader+=ntohs(addit[i].resource->datalen);
            }
            else{
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
            }
        }
    }

    //print answers
    printf("\nRegistros de respuestas : %d \n" , ntohs(dns->ancount) );
    
    if(iteracionIngresada==1)
    {
        if(necesitoIpNameserver==0)
        {
            if(ntohs(dns->ancount)>0)
                {
                seguirTrace=0;
                }    
        }
    }
    
    for(i=0 ; i < ntohs(dns->ancount) ; i++)
    {
        /*
        En caso de que la longitud del nombre sea cero y el tipo de query sea NS, en nuestro programa
        tenemos certeza de que es la llamada al ROOT.
        */
        if(strlen(answers[i].name)==0){
           if(query_type==2) 
            printf("Nombre : ROOT  ");
        }
        else{
            printf("Nombre : %s ",answers[i].name);
        }

        if( ntohs(answers[i].resource->type) == 1) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            printf("tiene la direccion IPv4 : %s",inet_ntoa(a.sin_addr));            
            if(iteracionIngresada==1){
            strcpy(proximo_server,inet_ntoa(a.sin_addr));
            }
            
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            printf("tiene un nombre de alias : %s",answers[i].rdata);
        }
        else
        {
            
            if(ntohs(answers[i].resource->type)==15){   //SI ES TIPO MX
                
                printf("Preferencia: %d  ",preferencia[i]);
                printf("Exchange: %s",answers[i].rdata);
                
            }
            else{
                if(ntohs(answers[i].resource->type)==29){   //SI ES TIPO LOC

                    printf("Coordenadas : %s",coordenadas);

                }
                else{                    
                    if(ntohs(answers[i].resource->type)==2){               //SI ES TIPO NS
                    printf("Nameserver: %s",answers[i].rdata);
                        if(necesitoIpNameserver==0)
                        {
                             nameservers[i]=answers[i].rdata;       //ANOTO NAMESERVERS
                             cantidadNS=ntohs(dns->ancount);        //Y LA CANTIDAD QUE HAY DE LOS MISMOS
                        }             
                    }
                }
                
                
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
            printf("Nameserver : %s",auth[i].rdata);
            if(iteracionIngresada==1)       //Si se ingreso -t
            {
              if(necesitoIpNameserver==0)   //No se necesita ip
              {  
                if(seguirTrace==1)
                {         //Y Vamos por bucle while
                    strcpy(nameservers[i],auth[i].rdata);       //ANOTO NAMESERVERS
                    cantidadNS=ntohs(dns->nscount);             //Y LA CANTIDAD QUE HAY DE LOS MISMOS
                }       
              }    
            }
        }
        printf("\n");
    }

    //print additional resource records
    printf("\nRegistros Adicionales : %d \n" , ntohs(dns->arcount) );
    
    int copiePrimerIp=0;
    int adicionalesNoPrinteables=0;
    for(i=0; i < ntohs(dns->arcount) ; i++)
    {
       
        if(ntohs(addit[i].resource->type)==1)
        {
            printf("Nombre : %s ",addit[i].name);
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("tiene la direccion IPv4 : %s",inet_ntoa(a.sin_addr));
            if(copiePrimerIp==0){
                strcpy(ipDisponibleEnAdicional,inet_ntoa(a.sin_addr));
                copiePrimerIp=1;
            }
            printf("\n"); 
        }
        else{
            adicionalesNoPrinteables++;
        }
        
    }
     if(iteracionIngresada==1){
            if((ntohs(dns->arcount)-adicionalesNoPrinteables)>0){ //Esto quiere decir que hay IPv4 que podemos usar
                
                strcpy(proximo_server,ipDisponibleEnAdicional);
                necesitoIpNameserver=0;
                //printf("EL PROXIMO SERVER ES %s \n", proximo_server);
                //exit(EXIT_FAILURE);
            }
            else{
                if(noEsDeInicio==1){
                necesitoIpNameserver=1;
                }
            }
        }


        memset(&answers[0], 0, sizeof(struct RESRECORD));
        memset(&auth[0], 0, sizeof(struct RESRECORD));
        memset(&addit[0], 0, sizeof(struct RESRECORD));

        printf("\n");

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
    memset(&dns_server[0], 0, sizeof(dns_server)); //elimina almacenado anteriormente
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        strncpy(dns_server, "8.8.8.8", strlen("8.8.8.8"));
    }

    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            char* aux;
            aux = strtok(line , " ");
            aux = strtok(NULL , " ");
            strncpy(dns_server, aux, strlen(aux)-1);
            dns_server[strlen ((const char*) dns_server)+1 ] = '\0';
            break;
            //p now is the dns ip :)
            //????
        }
    }
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
    int consulta,amxloc,rt,h,servidor;
    servidor=0;
    consulta=0;
    amxloc=0;
    rt=0;
    h=0;
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
            tipoQuery=T_A;     
        }
    else{    
    if(strcmp(argv[i],"-mx")==0)
    {
            if(amxloc==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            amxloc=1;
            tipoQuery=T_MX;        
    }       
    else{ 
    if(strcmp(argv[i],"-loc")==0)
    {
            if(amxloc==1) {
                printf("Parámetros excluyentes o repetidos \n");
                exit(EXIT_FAILURE);   
                  }
            amxloc=1;     
            tipoQuery=T_LOC;    
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
            iteracionIngresada=1;
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
             mostrarAyuda();//Imprimir ayuda
             exit(EXIT_FAILURE); // Y termino el programa
         }
         if(servidor==0){                  //No ingresaron servidor dns, hay que buscarlo en resolv.conf
                get_dns_servers();                
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
    else{                                  //Estamos en puerto! -> Registremos el numero luego del ':'
       puertoIngresado=1;                               
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

    
}


void append(char* s, char c)
{
        int len = strlen(s);
        s[len] = c;
        s[len+1] = '\0';
}

void consultaTrace(unsigned char *host, int query_type){
    
    
}

int random_number(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; // include max_num in output
    } else {
        low_num = max_num + 1; // include max_num in output
        hi_num = min_num;
    }

    srand(time(NULL));
    result = (rand() % (hi_num - low_num)) + low_num;
    return result;
}

void mostrarAyuda(){
   printf("*** Ayuda ***\n");
   printf("Uso:\n[-h] consulta [@servidor[:puerto]] [-a|-mx|-loc] [-r|-t]\nlas opciones entre corchetes son opcionales y las separadas por la barra vertical son alternativas excluyentes\n");
   printf("Significado:\n -h\t muestra las opciones a utilizar y sus funcionalidades\n ");
   printf("consulta\t dominio a resolver\n ");
   printf("@servidor\t servidor deseado que resolvera la consulta\n ");
   printf(":puerto\t debe usarse solamente con la opcion anterior. puerto deseado\n ");
   printf("-a\t usado por defecto. obtiene la direccion IP de 'consulta'\n ");
   printf("-mx\t obtiene el servidor a cargo de la recepcion de correos electronicos de 'consulta'\n");
   printf("-loc\t obtiene la ubicacion geografica de 'consulta'\n");
   printf("-r\t usado por defecto. obtiene la respuesta definitiva\n");
   printf("-t\t se visualizan las respuestas parciales producidas hasta obtener la respuesta definitiva\n");
}
