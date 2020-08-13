#include <pthread.h>

#define ENCRYPTION_BEGIN 1
#define ENCRYPTION_END   2
#define TERMINATE        3

unsigned char in [16] = "TOP SECRET MSG!"; // shared buffer
unsigned char out[16];

int p; // start and end flag
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


#define CPU0 9
#define CPU1 33