obj-m += procprotect.o

all:
	make -C /lib/modules/3.8.1-201.fc18.x86_64/build M=$(PWD) modules

clean:
	make -C /lib/modules/3.8.1-201.fc18.x86_64/build M=$(PWD) clean
