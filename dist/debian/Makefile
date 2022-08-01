include ./CONFIG

DEPENDS=
CROSSARCH=x64
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

DOCKCROSS=$(PWD)/../docker/dockcross
R2_LIBR_PLUGINS=/usr/lib/radare2/$(RV)

all: root
	$(MAKE) build

local: data
	$(MAKE) -C ../.. install DESTDIR=$(PWD)/root
	$(MAKE) build

data $(shell pwd)/data:
	sudo rm -rf control data
	${MAKE} clean
	rm -f data
	mkdir -p data
	cp -rf root/* data

build: data
	${MAKE} control
	${MAKE} deb

root:
	cd ../.. && $(DOCKCROSS) --image dockcross/linux-$(CROSSARCH) \
	bash -c 'DESTDIR=/work/dist/debian/root sh dist/debian/build.sh'

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
