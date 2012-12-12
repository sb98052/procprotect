obj-m += procprotect.o

all:
	make -C /usr/src/kernels/3.6.2-1.fc16.x86_64 M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
