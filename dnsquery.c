#include <stdio.h> //printf
#include <string.h> //memset()
#include <stdlib.h> //malloc, atoi()
#include <sys/socket.h> //socket(), connect(), send(), recv()
#include <arpa/inet.h> //inet_addr, etc.
#include <netinet/in.h>
#include <unistd.h> //getpid, close()
#include "location_reader.c" //funcion necesaria para leer consultas de tipo LOC
#include "dns_metodos_auxiliares.c" //funciones auxiliares necesarias

#include "dns_structs.h" //structs necesarios para estructura de consultas

#include "dns_declaraciones.h" //declaraciones de funciones posteriormente implementadas

/*  Autores: Raniolo Franco Martin - Amigo Leandro
*   Materia: Redes de Computadoras
*   Proyecto Mini-cliente de consultas DNS
*   Fecha de entrega: 3/6/2019
*   Universidad Nacional del Sur
*/

//Variables Globales necesarias
unsigned char hostname[100];
unsigned char dns_server[100];
unsigned char proximo_server[100];
unsigned char ipDisponibleEnAdicional[50];
char puerto[20]="";
unsigned short int tipoQuery = 1; //El tipo de query por defecto es tipo A
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


int main( int argc , char *argv[]){
     
    //Revisamos cantidad de argumentos

    if (argc>7 || argc<2){
        printf("Error: Cantidad inválida de argumentos (%d) \n",argc);
        exit(EXIT_FAILURE); 
    }
    
    //Realizamos la validacion de la consulta segun los parametros indicados en el enunciado
    validarConsulta(argc,argv);


    mensajeBienvenida();


    printf("Su servidor dns es %s\n",dns_server);    
    
    /*Revisamos si el usuario desea hacer trace o no
    * Si desea tracing, realizamos una consulta NS inicial hacia el servidor raiz
    * mediante el servidor ingresado o el ubicado en /etc/resolv.conf 
    * Sino, realizamos consulta con el bit de recursion encendido (rd) del dominio solicitado
    */
    
    if(iteracionIngresada==1){
    consultaTrace();
    }
    else{
     realizarConsulta(hostname,tipoQuery);   
    }

    return 0;
}

/*
 * 
 * Realiza una consulta DNS enviando un paquete
 * Lamentablemente no tuvimos tiempo suficiente para separar este metodo en varios (seria ideal),
 * pero aqui resumimos su funcionalidad:
 * - Primero se confecciona y se realiza la consulta UDP a traves de sockets
 * - Luego se leen todos los registros recibidos (de respuestas, autoritativos y adicionales) junto con el nombre
 * - Finalmente se imprime lo leido, en caso de ser posible. 
 * 
 * Parametros: 
 *  host: el dominio ingresado por el usuario 
 *  query_type: el tipo de consulta que desea realizar el usuario (A,MX,LOC,NS). Por defecto es A.
 * 
 * */

void realizarConsulta(unsigned char *host , int query_type){

 unsigned char buf[65536],*qname,*reader;
 
 int i , j , stop , s;
 
 struct sockaddr_in a;

 struct RESRECORD answers[20],auth[20],addit[20]; //Respuestas del servidor DNS

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

/*
* En caso de haber solicitado trace, se consideran una serie de casos para saber que servidor analizar.
*   -Si necesitamos realizar una consulta NS al root, se utilizara el servidor ingresado por el usuario o 
*    el que se encuentra en /etc/resolv.conf
*   -Si se necesita conocer el ip de un dominio, utilizaremos el mismo servidor indicado en el punto anterior.
*   -Sin embargo, para realizar el trace, necesitamos la ip del proximo servidor del arbol,
*     dicho servidor sera guardado en la variable proximo_server en caso de haberlo pedido a un dominio, o ya
*     haberlo recibido en un registro adicional en la consulta iterativa anterior. 
*       
*
*
*/
    if(iteracionIngresada==0){
    dest.sin_addr.s_addr =inet_addr(dns_server);
    }
    else{
        if(seguirTrace==0){
            dest.sin_addr.s_addr =inet_addr(dns_server); 
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
    /*
    *
    * Segun los casos definidos previamente a la hora de setear el servidor, en caso de necesitar el servidor ingresado
    * o el servidor ubicado en /etc/resolv.conf, el bit de recursion (rd) estara prendido. Mientras que en
    * caso de necesitar el servidor ubicado en proximo_server, quiere decir que realizaremos una consulta iterativa con el
    * bit de recursion apagado. (No queremos resolver el dominio recursivamente)
    * 
    */


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

    //apuntamos a la porcion de consulta
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
    
    CambioAFormatoDns(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
 
    qinfo->qtype = htons( query_type ); //Tipo de consulta , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //Es internet
 
    printf("\nEnviando Paquete...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Listo.");

    //Recibimos la respuesta
    i = sizeof dest;
    printf("\nRecibiendo respuesta...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Listo.");
 
    dns = (struct DNS_HEADER*) buf;

    
    //Movemos lector por delante del encabezado del dns y el campo de consulta
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nLa respuesta contiene : ");
    printf("\n %d Preguntas.",ntohs(dns->qdcount));
    printf("\n %d Respuestas.",ntohs(dns->ancount));
    printf("\n %d Servidores Autoritativos.",ntohs(dns->nscount));
    printf("\n %d Registros adicionales.\n\n",ntohs(dns->arcount));

    //Empezamos a leer respuestas
    stop=0;
 
    for(i=0;i<ntohs(dns->ancount);i++)
    {
        answers[i].name=leerNombre(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct RDATA*)(reader);
        reader = reader + sizeof(struct RDATA);


        if(ntohs(answers[i].resource->type) == 1) //Si es una direccion Ipv4
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
            answers[i].rdata = leerNombre(reader+2,buf,&stop);
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
                        answers[i].rdata = leerNombre(reader,buf,&stop);
                        reader = reader + stop;
                    }
                    else{              
                         answers[i].rdata = leerNombre(reader,buf,&stop);
                         reader = reader + stop;
                    }
                }
            }
        }
    }

    //Leemos registros autoritativos
    
    for(i=0;i<ntohs(dns->nscount);i++)
    {
        auth[i].name=leerNombre(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct RDATA*)(reader);
        reader+=sizeof(struct RDATA);
 
        auth[i].rdata=leerNombre(reader,buf,&stop);
        reader+=stop;
    }
    
    //Leemos registros adicionales
    for(i=0;i<ntohs(dns->arcount);i++)
    {
        //Leemos nombre
        addit[i].name=leerNombre(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct RDATA*)(reader);
        reader+=sizeof(struct RDATA);

        //Leemos registro
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->datalen));
            for(j=0;j<ntohs(addit[i].resource->datalen);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->datalen)]='\0';
            reader+=ntohs(addit[i].resource->datalen);
       
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
         
        printf("Nombre : %s ",auth[i].name);
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
    printf("Registros Adicionales ignorados (no imprimibles): %d \n",adicionalesNoPrinteables);

     if(iteracionIngresada==1){
            if((ntohs(dns->arcount)-adicionalesNoPrinteables)>0){ //Esto quiere decir que hay IPv4 que podemos usar
                
                strcpy(proximo_server,ipDisponibleEnAdicional);
                necesitoIpNameserver=0;
                
            }
            else{
                if(noEsDeInicio==1){
                necesitoIpNameserver=1;
                }
            }
        }

        printf("\n");

        printf("====================================================================================\n");

        //liberamos memoria reservada
        memset(&answers[0], 0, sizeof(struct RESRECORD));
        memset(&auth[0], 0, sizeof(struct RESRECORD));
        memset(&addit[0], 0, sizeof(struct RESRECORD));

        printf("\n");

   return;
} 

/*
 * 
 * Obtiene los servidores DNS del archivo /etc/resolv.conf en Linux
 * */
void obtener_dns_servers()
{
    FILE *fp;
    char line[200], *p;
    memset(&dns_server[0], 0, sizeof(dns_server)); //elimina almacenado anteriormente
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
    {
        strncpy(dns_server, "8.8.8.8", strlen("8.8.8.8"));
    }

    while (fgets(line, 200, fp))
    {
        if (line[0] == '#')
        {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0)
        {
            char *aux;
            aux = strtok(line, " ");
            aux = strtok(NULL, " ");
            strncpy(dns_server, aux, strlen(aux) - 1);
            dns_server[strlen((const char *)dns_server) + 1] = '\0';
            break;
            //Finalmente en dns_server tenemos el primer nameserver de resolv.conf
        }
    }
}


/*
*   Metodo con el objetivo de validar la consulta ingresada por el usuario
*   En caso de tener parametros excluyentes o repetidos, el programa le informara al usuario el error cometido.
*   Tambien registramos el tipo de consulta que desea hacer el usuario y si desea o no realizar trace. 
*   
*   En terminos de programador, el metodo simula un switch-case analizando los parametros ingresados por el usuario,
*   levantando flags en caso de haber insertado un parametro permitido.
*   
*   argc: Cantidad de parametros ingresados por el usuario
*   argv: Arreglo de cadenas de caracteres con los parametros ingresados
*/
void validarConsulta(int argc, char *argv[])
{
    int i = 0;
    int consulta, amxloc, rt, h, servidor;
    servidor = 0;
    consulta = 0;
    amxloc = 0;
    rt = 0;
    h = 0;
    char srv[20] = "";
    char arroba;

    for (i = 1; i < argc; i++)
    {

        if (strcmp(argv[i], "-h") == 0)
        {
            if (h == 1)
            {
                printf("Parámetro -h repetido \n");
                exit(EXIT_FAILURE);
            }
            h = 1;
        }
        else
        {
            if (strcmp(argv[i], "-a") == 0)
            {
                if (amxloc == 1)
                {
                    printf("Parámetros excluyentes o repetidos \n");
                    exit(EXIT_FAILURE);
                }
                amxloc = 1;
                tipoQuery = 1;
            }
            else
            {
                if (strcmp(argv[i], "-mx") == 0)
                {
                    if (amxloc == 1)
                    {
                        printf("Parámetros excluyentes o repetidos \n");
                        exit(EXIT_FAILURE);
                    }
                    amxloc = 1;
                    tipoQuery = 15;
                }
                else
                {
                    if (strcmp(argv[i], "-loc") == 0)
                    {
                        if (amxloc == 1)
                        {
                            printf("Parámetros excluyentes o repetidos \n");
                            exit(EXIT_FAILURE);
                        }
                        amxloc = 1;
                        tipoQuery = 29;
                    }
                    else
                    {
                        if (strcmp(argv[i], "-r") == 0)
                        {
                            if (rt == 1)
                            {
                                printf("Parámetros excluyentes o repetidos \n");
                                exit(EXIT_FAILURE);
                            }
                            rt = 1;
                        }
                        else
                        {
                            if (strcmp(argv[i], "-t") == 0)
                            {
                                if (rt == 1)
                                {
                                    printf("Parámetros excluyentes o repetidos \n");
                                    exit(EXIT_FAILURE);
                                }
                                rt = 1;
                                iteracionIngresada = 1;
                            }
                            else
                            {
                                if ('@' == argv[i][0]) //Si esto pasa es el servidor!
                                {
                                    if (servidor == 1)
                                    {
                                        printf("Ingrese un único servidor por favor.\n");
                                        exit(EXIT_FAILURE);
                                    }
                                    servidor = 1;
                                    strcpy(dns_server, argv[i]);
                                    eliminarArrobaDeString(dns_server);
                                }
                                else
                                { //Si llegué acá es una consulta!
                                    if (consulta == 1)
                                    {
                                        printf("Ingrese una única consulta por favor.\n");
                                        exit(EXIT_FAILURE);
                                    }
                                    strcpy(hostname, argv[i]);
                                    consulta = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    } //termina el for
    if (consulta == 0 && h == 0)
    { //No hay consulta y no pidió ayuda
        printf("Comando inválido. No hay consulta.\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        if (h == 1)
        {
            mostrarAyuda();     //Imprimir ayuda
            exit(EXIT_FAILURE); // Y termino el programa
        }
        if (servidor == 0)
        { //No ingresaron servidor dns, hay que buscarlo en resolv.conf
            obtener_dns_servers();
        }
    }
}

/*
*   Metodo utilizado para eliminar el caracter '@' del parametro del servidor
*   Ejemplo: "@8.8.8.8" => "8.8.8.8"
*   En caso de haber ingresado tambien un puerto, lo guardamos en una variable y lo eliminamos de la cadena de caracteres.
*   Ejemplo "@8.8.8.8:53" => "8.8.8.8"
*   La variable char *p sera la cadena de caracteres ingresado por el usuario para solicitar un servidor.
*/

void eliminarArrobaDeString(char *p)
{
    int yaElimineArroba = 0; //Variable para no borrar más arrobas en caso de que las haya
                             //(El usuario siempre es impredecible)
    char c = '@';
    int voyPorPuerto = 0; //En caso de que ya este por el puerto -> no registrarlo en servidor
    if (NULL == p)
        return;
    char *pDest = p; //Mismo que p (Apunta al principio del string)

    while (*p) //Saco el arroba
    {
        if (*p != ':' && voyPorPuerto == 0)
        { //Si no voy por puerto -> anoto servidor a no ser que sea @
            if (*p != c || yaElimineArroba == 1)
                *pDest++ = *p;
            else
            {
                yaElimineArroba = 1;
            }
        }
        else
        { //Estamos en puerto! -> Registremos el numero luego del ':'
            puertoIngresado = 1;
            if (voyPorPuerto == 0)
                voyPorPuerto = 1;
            else
            {

                append(puerto, *p); //Concatenamos uno de los numeros del puerto
            }
        }
        p++;
    }
    *pDest = '\0';
}

void consultaTrace()
{

    unsigned char prueba[100] = ""; //String vacio para solicitar consulta root

    realizarConsulta(prueba, 2); //Pedimos nameservers a Root

    if (cantidadNS < 1) //De no obtener dominios por el cual seguir, terminamos el programa
    {
        printf("No se han encontrado dominios para continuar la consulta solicitada. \n");
        exit(EXIT_FAILURE);
    }

    int r = random_number(0, cantidadNS - 1); //Calculamos index aleatorio para buscar en los nameservers

    printf("El root_nameserver aleatorio seleccionado es %s \n", nameservers[r]);

    realizarConsulta(nameservers[r], 1); //Pedimos ipv4 a nameserver de root aleatorio
    printf("El proximo server es : %s\n", proximo_server);
    noEsDeInicio = 1; //Booleano necesario para detectar comienzo de bucle (la configuracion es distinta en el bucle)
    seguirTrace = 1;  //Booleano necesario para controlar el seguimiento y detencion del bucle
    //Inicio del bucle
    while (seguirTrace)
    {
        if (necesitoIpNameserver == 0)      //si no necesito ip puedo realizar consulta iterativa con bit rd apagado
        {
            realizarConsulta(hostname, tipoQuery);
            hostname[strlen(hostname) - 1] = '\0'; //Eliminamos el punto agregado por el metodo anterior.
            if (seguirTrace == 1)
            {
                printf("El proximo server es : %s\n", proximo_server);
            }
        }
        else
        { //Necesito ip de un nameserver, en caso de no haberlos lanzo error.

            if (cantidadNS < 1)
            {
                printf("Error: cantidad nameservers nula \n");
                exit(EXIT_FAILURE);
            }
            r = random_number(0, cantidadNS - 1); //obtenemos un index aleatorio para elegir un nameserver
            printf("El root_nameserver aleatorio es %s \n", nameservers[r]);
            realizarConsulta(nameservers[r], 1); //Pedimos ipv4 a nameserver de root aleatorio
            necesitoIpNameserver = 0; //ya no necesito un ip
        }
    }
}