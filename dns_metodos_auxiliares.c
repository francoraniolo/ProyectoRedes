
//Metodo utilizado para especificarle al usuario el estandar necesario para realizar consultas. 
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

/*
*   Metodo utilizado para obtener un numero aleatorio 
*   ubicado entre un numero minimo y maximo pasados por parametro.
*
*/
int random_number(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; 
    }
    else
    {
        low_num = max_num + 1; 
        hi_num = min_num;
    }

    srand(time(NULL));
    result = (rand() % (hi_num - low_num)) + low_num;
    return result;
}

//Metodo para concatenar caracteres

void append(char *s, char c)
{
    int len = strlen(s);
    s[len] = c;
    s[len + 1] = '\0';
}

/*
 * Esto realizará la conversión de dominios como www.google.com a 3www6google3com 
 * 
 * */
void CambioAFormatoDns(unsigned char *dns, unsigned char *host)
{
    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++ = '\0';
}


/*
*   Metodo para leer el campo nombre del registro
*   Parametros:
*   reader: puntero lector 
*   buffer,
*   contador para mantener en una variable el numero de pasos que avanzamos a traves del paquete
*
*
*/

unsigned char* leerNombre(unsigned char* reader,unsigned char* buffer,int* count)
{

    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
    
    //Leemos los nombres en formato como 3www6google3com
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000
            reader = buffer + offset - 1;
            jumped = 1; //Se salto a otra ubicacion
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {                          
            *count = *count + 1; //Si no se salto a otra ubicacion podemos sumar contador.
        }
    }
 
    name[p]='\0'; //string completo
    if(jumped==1)
    {                         
        *count = *count + 1; //numero de pasos que avanzamos a traves del paquete.
    }
 
    //Conversion de dominios como 3www6google3com0 a www.google.com
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
    name[i-1]='\0'; //remuevo el ultimo punto
    return name;
}

void mensajeBienvenida(){

printf("  =================================================================================\n");
printf("  Mini-Cliente de consulta de servidores DNS - <PROYECTO DE REDES DE COMPUTADORAS>  \n");
printf("  Universidad Nacional del Sur    \n");
printf("  =================================================================================\n");

printf("  Alumnos: Raniolo Franco Martin - Amigo Leandro\n");

printf("  =================================================================================\n");


printf("<D N S   Q U E R Y>\n");
printf("\n");

}