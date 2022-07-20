## Prime+Probe attack on AES

### Attack summary
This attack runs on linux with root privilege. Attack runs on L1 data cache and requires hyperthreading feature of an Intel CPU.

### Attack Target
AES in OpenSSL, one who wants to run this attack must compile OpenSSL with `no-asm` flag.
```bash
$ cd OPENSSL_DIR
$ ./config no-asm
$ make
```

### Attack Environment
A linux kernel with version>4 is needed. Compile and install MSR driver in directory `pmc_driver/`. Then complie sources in `pmc_events/` by simply executing `make` in that directory.
Our attack implementation uses `rdpmc` instruction to read L1D cache miss performence counter to achieve *probe* process. But normally `rdpmc` instruction is disabled in userspace so  `echo 2 | sudo tee /sys/devices/cpu/rdpmc` to enable it with sudo privilege. Then cd to `pmc_events` and execute `setup.sh` with root privilege to setup L1d cache miss counters in cpu cores.

### Attack Setup
After manually building openssl, alter the `OPENSSL=` option in `config.in` file to the openssl folder you build. Use `readelf -s libcrypto.so | grep Te[0-4]`  to determine the address of T-tables and fill them correspondingly into `config.in`.
One may also need to alter the CPU numbers in `common.h` which `CPU0` and `CPU1` is the number of CPU the attacker and victim runs on respectively. `CPU0` and `CPU1` must be two defferent logical cores running on a same physical core which be easily determined by `cat /proc/cpuinfo`.
Execute `sudo LD_LIBRARY_PATH=${OPENSSL_DIR} ./spy >data.txt` in `L1` directory to run an attack demo and information will be gathered into data.txt.
