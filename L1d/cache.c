#include "cache.h"
#include <stdio.h>
#include <string.h>
#include <cpuid.h>


static int alignment_dummy __attribute__ ((aligned(4096)));
static int alignment_dummy2 __attribute__ ((aligned(1024)));

static size_t round, table;
static size_t i, j;
static uint32_t t1, t2, mean;
static unsigned int local_hits_single, local_hits_sum;
static int pmccount;
static int pmc1, pmc2;	   //counter values before and after each test

/*
 * Force cpu to serialize instructions
 */
static inline void serialize () {
	__asm __volatile__ ("cpuid" : : "a"(0) : "ebx", "ecx", "edx" );  // serialize
}

/*
 * Read performance-counter instruction
 */
static inline uint64_t readpmc(int32_t n) {
	uint32_t lo, hi;
	__asm __volatile__ ("rdpmc" : "=a"(lo), "=d"(hi) : "c"(n) : );
	return lo | (uint64_t)hi << 32;
}

static uint64_t readtsc(int unused) {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}


/*
 * Access a single cacheline in order to load it into the L1 cache.
 */
unsigned int prime_single(size_t entry, const uint8_t *table, size_t tablesize){
	__asm__ __volatile__(
					"cpuid				\n"
					/* Remove from every cache level */
					"movq (%%rsi), %%rbx\n"
					"cpuid				\n"
					: /* output operands */
					: /* input operands */
					"S" (table + CACHELINESIZE * entry)
					: /* clobber description */
					"ebx", "ecx", "edx", "cc"
		);
	return 0;
}

/*
 * Access single cachline and check PMC for L1-Cache miss.
 */
unsigned int measure_pmc(size_t entry, const uint8_t *table, size_t tablesize){
	local_hits_single = 0;
	serialize();					//prevent out-of-order execution
	pmc1= (int)readpmc(pmc_num);	//read PMC

	__asm__ __volatile__(
			"movq (%%rsi), %%rbx\n"
			: /* output operands */
			: /* input operands */
			"S" (table + CACHELINESIZE * entry)
			: /* clobber description */
			"ebx", "ecx", "edx", "cc", "memory"
		);

	serialize();					// serialize again
	pmc2= (int)readpmc(pmc_num);
	pmccount = pmc2-pmc1;
	return pmccount;
}

uint64_t rdtsc() {
  uint64_t a, d;// prevent out of order execution
  asm volatile ("cpuid\n"
  				"rdtsc\n" 
				"cpuid\n" 
				: "=a" (a), "=d" (d));
  a = (d<<32) | a;
  return a;
}


unsigned int measure_time(size_t entry, const uint8_t *table, size_t tablesize){
	local_hits_single = 0;
 	uint64_t a, b;
	a = rdtsc();
	__asm__ __volatile__(
			"movq (%%rsi), %%rbx\n"
			:/* output operands */
			: /* input operands */
			"S" (table + CACHELINESIZE * entry)
			: /* clobber description */
			"ebx", "ecx", "edx", "cc", "memory"
		);

	b = rdtsc();
	return b - a;
}

/*
 * Evict whole table from cache.
 */
unsigned int evict(const uint8_t *table, size_t tablesize, uint8_t *bitmap){
		for (i = 0; i < tablesize/CACHELINESIZE; i++) {
				__asm__ (
								"clflush (%%rsi)	 \n"
				: /* output operands */
				: /* input operands */
								"S" (table + CACHELINESIZE * i)
				: /* clobber description */
								"ebx", "ecx", "edx", "cc"
				);
	}
	return 0;
}

/*
 * Check for evicted cacheline in all cache-sets.
 */
unsigned int probe(size_t index) {
	int sum = 0;
	for (table = 0; table < NUM_TABLES; table++) {
		sum += measure_pmc(index, (const uint8_t *) tables[table], TABLESIZE);
	}
	//printf("Index %d:%d\", index, local_hits_sum);
	return sum != 0;	
}

/*
 * Fill all cache-lines in every cache-set.
 */
void prime(size_t set_start, size_t set_end) {
	for (round = 0; round < PRIME_COUNT; round++){
			for (table = 0; table < NUM_TABLES; table++) {
				for(size_t set = set_start; set <= set_end; set++){
					prime_single(set, (const uint8_t *) tables[table], TABLESIZE);
				}
			}
	}
}
