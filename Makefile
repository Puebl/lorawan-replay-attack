APPLICATION = lorawan_replay_attack


BOARD ?= unwd-range-l1-r3


RIOT_BASE ?= $(CURDIR)/../../RIOT


LORA_DRIVER ?= sx1276


LORAWAN_REGION ?= EU868


USEPKG += semtech-loramac


INCLUDE_DIRS += -I$(CURDIR)/include


include $(RIOTBASE)/Makefile.include
