//Declaraciones de funciones
void realizarConsulta(unsigned char *host , int query_type);

u_char* leerNombre(unsigned char* reader,unsigned char* buffer,int* count);

void obtener_dns_servers();

void CambioAFormatoDns(unsigned char* dns,unsigned char* host);

void validarConsulta(int argc, char *argv[]);

void eliminarArrobaDeString(char* p);

void append(char* s, char c);

void guardarPuerto(char* p);

void consultaTrace();

int random_number(int min_num, int max_num);

void mostrarAyuda();

void mensajeBienvenida();

