KERNEL := 8127
NAME := virtualchar
PWD := $(shell pwd)
obj-m += $(NAME).o

ifeq ($(KERNEL),8127)
PRODUCT_NAME := hangshijie_v12
KERNELDIR ?= /home/glz/work/git/mtk/mt8127_jb_0516/out/target/product/$(PRODUCT_NAME)/obj/KERNEL_OBJ
CROSS_TOOLS = /home/glz/work/git/mtk/mt8127_jb_0516/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.7/bin/arm-linux-androideabi-
OBJDUMPFLAGS = -D -S
modules:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules TARGET_PRODUCT=$(PRODUCT_NAME) CROSS_COMPILE=$(CROSS_TOOLS)
	@$(CROSS_TOOLS)objdump $(OBJDUMPFLAGS)  $(NAME).ko > $(NAME).dis
else
modules:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

all:modules

.PHONY: clean
clean:
	@-rm -rf *.o *.ko *mod* Module.symvers .tmp* .*.cmd *.dis 
	
