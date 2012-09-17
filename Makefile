obj-m += procprotect.o

all:
	make -C /lib/modules/3.4.9-2.fc16.x86_64/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
