include config.in
export 

MASTIK = "Mastik/src"
LD_LIBRARY_PATH = $(OPENSSL)

all: spy

spy: 
	gcc cache.c set_sched.c attack.c -DMACROS -DTABLE0=$(TABLE0) -DTABLE1=$(TABLE1) -DTABLE2=$(TABLE2) -DTABLE3=$(TABLE3) -DTHRESHOLD=$(THRESHOLD)  -L$(OPENSSL) -I$(OPENSSL)/include -Wno-deprecated-declarations -lcrypto -lpthread -std=gnu11 -o spy


clean:
	rm -f *.o spy