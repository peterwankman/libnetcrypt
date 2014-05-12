BIN=bin
OBJ=objects
CC=gcc

TSTSRC=testprog
TOMSRC=libtommath
LIBSRC=libnetcrypt

CFLAGS=-O0 -ggdb -I$(LIBSRC) -L$(BIN) -DWITH_AES -DWITH_CAST6 -DWITH_SHA256
LDFLAGS=-L$(BIN) -lnetcrypt -ltommath

all:
	make $(BIN)/testprog
	make $(BIN)/libnetcrypt.a

clean:
	rm -f $(OBJ)/*
	rm -f $(BIN)/*
	rm -f $(TOMSRC)/*.o
	rm -f $(TOMSRC)/*.a

$(BIN)/testprog: $(BIN)/libnetcrypt.a $(BIN)/libtommath.a $(OBJ)/getopt.o $(TSTSRC)/testprog.c
	$(CC) $^ $(LDFLAGS) $(CFLAGS) -o $@

$(OBJ)/getopt.o: $(TSTSRC)/getopt.c
	$(CC) $(CFLAGS) -c -o  $@ $^

$(BIN)/libtommath.a: $(TOMSRC)/makefile
	make -C $(TOMSRC)
	cp $(TOMSRC)/libtommath.a $(BIN)

$(BIN)/libnetcrypt.a: $(BIN)/libtommath.a $(OBJ)/lnc_aes.o \
$(OBJ)/lnc_cast6.o \
$(OBJ)/lnc_dh.o \
$(OBJ)/lnc_error.o \
$(OBJ)/lnc_main.o \
$(OBJ)/lnc_proto.o \
$(OBJ)/lnc_reg.o \
$(OBJ)/lnc_rndart.o \
$(OBJ)/lnc_sha256.o \
$(OBJ)/lnc_util.o
	ar -rcs $@ $^

$(OBJ)/lnc_aes.o: $(LIBSRC)/lnc_aes.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_cast6.o: $(LIBSRC)/lnc_cast6.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_dh.o: $(LIBSRC)/lnc_dh.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_error.o: $(LIBSRC)/lnc_error.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_main.o: $(LIBSRC)/lnc_main.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_proto.o: $(LIBSRC)/lnc_proto.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_reg.o: $(LIBSRC)/lnc_reg.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_rndart.o: $(LIBSRC)/lnc_rndart.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_sha256.o: $(LIBSRC)/lnc_sha256.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(OBJ)/lnc_util.o: $(LIBSRC)/lnc_util.c
	$(CC) $(CFLAGS) -c -o $@ $^


