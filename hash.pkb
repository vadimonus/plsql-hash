create or replace PACKAGE BODY HASH
AS
  
  TYPE TA_NUMBER IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;
  
  TYPE TR_CTX IS RECORD (
    H TA_NUMBER,
    TOTAL TA_NUMBER,
    BUFLEN NUMBER,
    BUFFER32 TA_NUMBER
  );

  /* Constant for 32bit bitwise operations */
  BITS_FFFFFFFF NUMBER := TO_NUMBER('FFFFFFFF','xxxxxxxx');
  BITS_FF000000 NUMBER := TO_NUMBER('FF000000','xxxxxxxx');
  BITS_00FF0000 NUMBER := TO_NUMBER('00FF0000','xxxxxxxx');
  BITS_0000FF00 NUMBER := TO_NUMBER('0000FF00','xxxxxxxx');
  BITS_000000FF NUMBER := TO_NUMBER('000000FF','xxxxxxxx');
  BITS_00FFFFFF NUMBER := TO_NUMBER('00FFFFFF','xxxxxxxx');
  BITS_FF00FFFF NUMBER := TO_NUMBER('FF00FFFF','xxxxxxxx');
  BITS_FFFF00FF NUMBER := TO_NUMBER('FFFF00FF','xxxxxxxx');
  BITS_FFFFFF00 NUMBER := TO_NUMBER('FFFFFF00','xxxxxxxx');
  BITS_FFFF0000 NUMBER := TO_NUMBER('FFFF0000','xxxxxxxx');
  BITS_80000000 NUMBER := TO_NUMBER('80000000','xxxxxxxx');
  BITS_00800000 NUMBER := TO_NUMBER('00800000','xxxxxxxx');
  BITS_00008000 NUMBER := TO_NUMBER('00008000','xxxxxxxx');
  BITS_00000080 NUMBER := TO_NUMBER('00000080','xxxxxxxx');
  BITS_FFFFFFC0 NUMBER := TO_NUMBER('FFFFFFC0','xxxxxxxx');
  
FUNCTION dec2bin (N IN NUMBER) RETURN VARCHAR2 IS
  binval VARCHAR2(64);
  N2     NUMBER := N;
BEGIN
  WHILE ( N2 > 0 ) LOOP
     binval := MOD(N2, 2) || binval;
     N2 := TRUNC( N2 / 2 );
  END LOOP;
  RETURN binval;
END dec2bin;

FUNCTION BITOR(X IN NUMBER, Y IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN (X + Y - BITAND(X, Y));
  END;

  FUNCTION BITXOR(X IN NUMBER, Y IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITOR(X, Y) - BITAND(X, Y);
  END;

  FUNCTION BITNOT(X IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITS_FFFFFFFF - X;
  END;

  FUNCTION LEFTSHIFT(X IN NUMBER, Y IN NUMBER) RETURN NUMBER AS
    TMP NUMBER := X;
  BEGIN
    FOR IDX IN 1..Y LOOP
      TMP := TMP * 2;
    END LOOP;
    RETURN BITAND(TMP, BITS_FFFFFFFF);
  END;

  FUNCTION RIGHTSHIFT(X IN NUMBER, Y IN NUMBER) RETURN NUMBER AS
    TMP NUMBER := X;
  BEGIN
    FOR IDX IN 1..Y LOOP
      TMP := TRUNC(TMP / 2);
    END LOOP;
    RETURN BITAND(TMP, BITS_FFFFFFFF);
  END;

  FUNCTION CYCLIC(X IN NUMBER, Y IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITOR( RIGHTSHIFT(X, Y), LEFTSHIFT(X, 32-Y) );
  END;

/* Operators defined in FIPS 180-2:4.1.2.  */
  FUNCTION OP_F0019(B IN NUMBER, C IN NUMBER, D IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITOR(BITAND(B, C), (BITAND(BITNOT(B),D)));
  END;

  FUNCTION OP_F2039(B IN NUMBER, C IN NUMBER, D IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR(BITXOR(B, C), D);
  END;

  FUNCTION OP_F4059(B IN NUMBER, C IN NUMBER, D IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITOR(BITOR(BITAND(B, C), BITAND(B, D)), BITAND(C, D));
  END;
  
  FUNCTION OP_F6079(B IN NUMBER, C IN NUMBER, D IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR(BITXOR(B, C), D);
  END;

  FUNCTION OP_CH(X IN NUMBER, Y IN NUMBER, Z IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR( BITAND(X, Y), BITAND(BITNOT(X), Z) );
  END;

  FUNCTION OP_MAJ(X IN NUMBER, Y IN NUMBER, Z IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR( BITXOR( BITAND(X,Y), BITAND(X,Z) ), BITAND(Y,Z) );
  END;

  FUNCTION OP_S0(X IN NUMBER) RETURN NUMBER AS 
  BEGIN
    RETURN BITXOR( BITXOR( CYCLIC(X,2), CYCLIC(X,13) ), CYCLIC(X,22) );
  END;
  
  FUNCTION OP_S1(X IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR( BITXOR( CYCLIC(X, 6), CYCLIC(X, 11) ), CYCLIC(X, 25) );
  END;

  FUNCTION OP_R0(X IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR( BITXOR( CYCLIC(X, 7), CYCLIC(X, 18) ), RIGHTSHIFT(X, 3) );
  END;

  FUNCTION OP_R1(X IN NUMBER) RETURN NUMBER AS
  BEGIN
    RETURN BITXOR( BITXOR( CYCLIC(X, 17), CYCLIC(X, 19) ), RIGHTSHIFT(X, 10) );
  END;

  FUNCTION SHA1(X IN RAW) RETURN SHA1_CHECKSUM_RAW AS
    CTX TR_CTX;
    FILLBUF TA_NUMBER; 
    RES TA_NUMBER;

    PROCEDURE SHA1_INIT_CTX AS
    BEGIN
      CTX.H(0)     := TO_NUMBER('67452301', 'xxxxxxxx');
      CTX.H(1)     := TO_NUMBER('efcdab89', 'xxxxxxxx');
      CTX.H(2)     := TO_NUMBER('98badcfe', 'xxxxxxxx');
      CTX.H(3)     := TO_NUMBER('10325476', 'xxxxxxxx');
      CTX.H(4)     := TO_NUMBER('c3d2e1f0', 'xxxxxxxx');
      CTX.TOTAL(0) := 0;
      CTX.TOTAL(1) := 0;
      CTX.BUFLEN   := 0;
      FOR IDX IN 0..32 LOOP
        CTX.BUFFER32(IDX) := 0;
      END LOOP;

      FILLBUF(0) := BITS_80000000;
      FOR I IN 1..7 LOOP
        FILLBUF(I) := 0;
      END LOOP;
    END;

    PROCEDURE SHA1_PROCESS_BLOCK(BUFFER IN TA_NUMBER, LEN IN NUMBER) AS
      WORDS TA_NUMBER := BUFFER;
      NWORDS    NUMBER   := TRUNC(LEN / 4);
      POS_WORDS NUMBER;
      T         NUMBER;
      A         NUMBER := CTX.H(0);
      B         NUMBER := CTX.H(1);
      C         NUMBER := CTX.H(2);
      D         NUMBER := CTX.H(3);
      E         NUMBER := CTX.H(4);
      W TA_NUMBER; --//[80] ;
      A_SAVE NUMBER;
      B_SAVE NUMBER;
      C_SAVE NUMBER;
      D_SAVE NUMBER;
      E_SAVE NUMBER;
      F     NUMBER;
      K     NUMBER;
      TEMP  NUMBER;
    BEGIN
      /* First increment the byte count.  FIPS 180-2 specifies the possible length of the file up to 2^64 bits. Here we only compute the number of bytes.  */
      CTX.TOTAL(1) := CTX.TOTAL(1) + LEN;
      /* Process all bytes in the buffer with 64 bytes in each round of the loop.  */
      POS_WORDS := 0;
      WHILE (NWORDS > 0) LOOP
        A_SAVE := A;
        B_SAVE := B;
        C_SAVE := C;
        D_SAVE := D;
        E_SAVE := E;
        FOR T IN 0..15 LOOP
          W(T)      := WORDS(POS_WORDS);
          POS_WORDS := POS_WORDS + 1;
        END LOOP;
        FOR T IN 16..79 LOOP
          W(T) := CYCLIC(BITXOR(BITXOR(BITXOR(W(T-3), W(T-8)), W(T-14)), W(T-16)), 32-1);
        END LOOP;
        FOR T IN 0..79 LOOP
          IF T BETWEEN 0 AND 19 THEN
            F := BITOR(BITAND(B, C), BITAND(BITNOT(B), D));
            K := TO_NUMBER('5a827999', 'xxxxxxxx');
          ELSIF T BETWEEN 20 AND 39 THEN
            F := BITXOR(BITXOR(B, C), D);
            K := TO_NUMBER('6ed9eba1', 'xxxxxxxx');
          ELSIF T BETWEEN 40 AND 59 THEN
            F := BITOR(BITOR(BITAND(B, C), BITAND(B, D)), BITAND(C, D));
            K := TO_NUMBER('8f1bbcdc', 'xxxxxxxx');
          ELSIF T BETWEEN 60 AND 79 THEN
            F := BITXOR(BITXOR(B, C), D);
            K := TO_NUMBER('ca62c1d6', 'xxxxxxxx');
          END IF;

          TEMP := BITAND(CYCLIC(A, 32-5) + F + E + K + W(T), BITS_FFFFFFFF);
          E := D;
          D := C;
          C := CYCLIC(B, 32-30);
          B := A;
          A := TEMP;

        END LOOP;

        A := BITAND(A + A_SAVE, BITS_FFFFFFFF);
        B := BITAND(B + B_SAVE, BITS_FFFFFFFF);
        C := BITAND(C + C_SAVE, BITS_FFFFFFFF);
        D := BITAND(D + D_SAVE, BITS_FFFFFFFF);
        E := BITAND(E + E_SAVE, BITS_FFFFFFFF);
        /* Prepare for the next round.  */
        NWORDS := NWORDS - 16;
      END LOOP;
      /* Put checksum in context given as argument.  */
      CTX.H(0) := A;
      CTX.H(1) := B;
      CTX.H(2) := C;
      CTX.H(3) := D;
      CTX.H(4) := E;
    END;

    PROCEDURE SHA1_PROCESS_BYTES(BUFFER IN RAW, LEN IN NUMBER) AS
      LEFT_OVER     NUMBER;
      LEFT_OVER_BLK NUMBER;
      LEFT_OVER_MOD NUMBER;
      ADD           NUMBER;
      T_LEN         NUMBER          := LEN;
      T_BUFFER      RAW(16384) := BUFFER;
      X_BUFFER32 TA_NUMBER;
    BEGIN
      /* When we already have some bits in our internal buffer concatenate both inputs first.  */
      IF (CTX.BUFLEN > 0) THEN
        LEFT_OVER   := CTX.BUFLEN;
        IF 128 - LEFT_OVER > T_LEN THEN
          ADD := T_LEN;
        ELSE
          ADD := 128 - LEFT_OVER;
        END IF;
        FOR IDX IN 1..ADD LOOP
          LEFT_OVER_BLK := TRUNC((LEFT_OVER + IDX - 1)/4);
          LEFT_OVER_MOD := MOD((LEFT_OVER + IDX - 1), 4);
          IF (LEFT_OVER_MOD = 0) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
          ELSIF (LEFT_OVER_MOD = 1) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
          ELSIF (LEFT_OVER_MOD = 2) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
          ELSE
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
          END IF;
        END LOOP;
        CTX.BUFLEN    := CTX.BUFLEN + ADD;
        IF (CTX.BUFLEN > 64) THEN
          SHA1_PROCESS_BLOCK (CTX.BUFFER32, BITAND(CTX.BUFLEN, BITS_FFFFFFC0));
          CTX.BUFLEN := BITAND(CTX.BUFLEN, 63);
          /* The regions in the following copy operation cannot overlap.  */
          /* memcpy (ctx->buffer, ￡|ctx->buffer[(left_over + add) ￡| ~63], ctx->buflen); */
          FOR IDX IN 1..CTX.BUFLEN
          LOOP
            DECLARE
              DEST_POS     NUMBER := IDX           -1;
              DEST_POS_BLK NUMBER := TRUNC(DEST_POS/4);
              DEST_POS_MOD NUMBER := MOD(DEST_POS, 4);
              SRC_POS      NUMBER := BITAND(LEFT_OVER + ADD, BITS_FFFFFFC0)+IDX-1;
              SRC_POS_BLK  NUMBER := TRUNC(SRC_POS    /4);
              SRC_POS_MOD  NUMBER := MOD(SRC_POS, 4);
              BYTE_VALUE   NUMBER;
            BEGIN
              IF (SRC_POS_MOD   =0) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_FF000000)/16777216;
              ELSIF (SRC_POS_MOD=1) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_00FF0000)/65536;
              ELSIF (SRC_POS_MOD=2) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_0000FF00)/256;
              ELSE
                BYTE_VALUE := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_000000FF);
              END IF;
              IF (DEST_POS_MOD              =0) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_00FFFFFF) + BYTE_VALUE*16777216;
              ELSIF (DEST_POS_MOD           =1) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FF00FFFF) + BYTE_VALUE*65536;
              ELSIF (DEST_POS_MOD           =2) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFF00FF) + BYTE_VALUE*256;
              ELSE
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFFFF00) + BYTE_VALUE;
              END IF;
            END;
          END LOOP;
        END IF;
        T_BUFFER := UTL_RAW.SUBSTR(T_BUFFER, ADD+1);
        T_LEN    := T_LEN               - ADD;
      END IF;
      /* Process available complete blocks.  */
      IF (T_LEN >= 64) THEN
        DECLARE
          CNT        NUMBER := BITAND(T_LEN, BITS_FFFFFFC0);
          TARGET_BLK NUMBER;
          TARGET_MOD NUMBER;
        BEGIN
          FOR IDX IN 0..CNT
          LOOP
            X_BUFFER32(IDX) := 0;
          END LOOP;
          FOR IDX IN 1..CNT
          LOOP
            TARGET_BLK               := TRUNC((IDX-1)/4);
            TARGET_MOD               := MOD((IDX  -1), 4);
            IF (TARGET_MOD            =0) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
            ELSIF (TARGET_MOD         =1) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
            ELSIF (TARGET_MOD         =2) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
            ELSE
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
            END IF;
          END LOOP;
          SHA1_PROCESS_BLOCK (X_BUFFER32, CNT);
          T_BUFFER := UTL_RAW.SUBSTR(T_BUFFER, CNT+1);
        END;
        T_LEN := BITAND(T_LEN, 63);
      END IF;
      /* Move remaining bytes into internal buffer.  */
      IF (T_LEN    > 0) THEN
        LEFT_OVER := CTX.BUFLEN;
        /* memcpy (￡|ctx->buffer[left_over], t_buffer, t_len); */
        FOR IDX IN 1..T_LEN
        LOOP
          LEFT_OVER_BLK                 := TRUNC((LEFT_OVER+IDX-1)/4);
          LEFT_OVER_MOD                 := MOD((LEFT_OVER  +IDX-1), 4);
          IF (LEFT_OVER_MOD              =0) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
          ELSIF (LEFT_OVER_MOD           =1) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
          ELSIF (LEFT_OVER_MOD           =2) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
          ELSE
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
          END IF;
        END LOOP;
        LEFT_OVER     := LEFT_OVER + T_LEN;
        IF (LEFT_OVER >= 64) THEN
          SHA1_PROCESS_BLOCK (CTX.BUFFER32, 64);
          LEFT_OVER := LEFT_OVER - 64;
          /* memcpy (ctx->buffer, ￡|ctx->buffer[64], left_over); */
          FOR IDX IN 1..LEFT_OVER
          LOOP
            DECLARE
              DEST_POS     NUMBER := IDX           -1;
              DEST_POS_BLK NUMBER := TRUNC(DEST_POS/4);
              DEST_POS_MOD NUMBER := MOD(DEST_POS, 4);
              SRC_POS      NUMBER := IDX          +64-1;
              SRC_POS_BLK  NUMBER := TRUNC(SRC_POS/4);
              SRC_POS_MOD  NUMBER := MOD(SRC_POS, 4);
              BYTE_VALUE   NUMBER;
            BEGIN
              IF (SRC_POS_MOD   =0) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_FF000000)/16777216;
              ELSIF (SRC_POS_MOD=1) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_00FF0000)/65536;
              ELSIF (SRC_POS_MOD=2) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_0000FF00)/256;
              ELSE
                BYTE_VALUE := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_000000FF);
              END IF;
              IF (DEST_POS_MOD              =0) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_00FFFFFF) + BYTE_VALUE*16777216;
              ELSIF (DEST_POS_MOD           =1) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FF00FFFF) + BYTE_VALUE*65536;
              ELSIF (DEST_POS_MOD           =2) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFF00FF) + BYTE_VALUE*256;
              ELSE
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFFFF00) + BYTE_VALUE;
              END IF;
            END;
          END LOOP;
        END IF;
        CTX.BUFLEN := LEFT_OVER;
      END IF;
    END;

    PROCEDURE SHA1_FINISH_CTX(RESBUF OUT NOCOPY TA_NUMBER) AS
      BYTES     NUMBER := CTX.BUFLEN;
      PAD       NUMBER;
      PAD_IN    NUMBER;
      PAD_OUT   NUMBER;
      START_IDX NUMBER;
      I         NUMBER;
    BEGIN
      /* Now count remaining bytes.  */
      CTX.TOTAL(1) := CTX.TOTAL(1)+BYTES;
      /* Fill left bytes. */
      IF (BYTES >= 56) THEN
        PAD     := 64 + 56 - BYTES;
      ELSE
        PAD := 56 - BYTES;
      END IF;
      PAD_IN                      := 4     - MOD(BYTES,4);
      PAD_OUT                     := PAD   - PAD_IN;
      START_IDX                   := (BYTES-MOD(BYTES,4))/4;
      IF (PAD_IN                   < 4) THEN
        IF (PAD_IN                 = 1) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FFFFFF00) + BITS_00000080;
        ELSIF (PAD_IN              = 2) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FFFF0000) + BITS_00008000;
        ELSIF (PAD_IN              = 3) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FF000000) + BITS_00800000;
        END IF;
        FOR IDX IN (START_IDX+1)..(START_IDX+1+PAD_OUT/4-1)
        LOOP
          CTX.BUFFER32(IDX) := 0;
        END LOOP;
      ELSE
        FOR IDX IN START_IDX..(START_IDX+PAD/4-1)
        LOOP
          IF (IDX              = START_IDX) THEN
            CTX.BUFFER32(IDX) := BITS_80000000;
          ELSE
            CTX.BUFFER32(IDX) := 0;
          END IF;
        END LOOP;
      END IF;
      /* Put the 64-bit file length in *bits* at the end of the buffer.  */
      CTX.BUFFER32((BYTES                       + PAD + 4) / 4) := BITAND(CTX.TOTAL(1) * 8, BITS_FFFFFFFF);
      CTX.BUFFER32((BYTES                       + PAD) / 4)     := BITOR ( BITAND(CTX.TOTAL(0) * 8, BITS_FFFFFFFF), BITAND(CTX.TOTAL(1) / 536870912, BITS_FFFFFFFF) );
      SHA1_PROCESS_BLOCK (CTX.BUFFER32, BYTES + PAD + 8);
      FOR IDX                                  IN 0..4
      LOOP
        RESBUF(IDX) := CTX.H(IDX);
      END LOOP;
    END;

  BEGIN
    SHA1_INIT_CTX;
    SHA1_PROCESS_BYTES(X, UTL_RAW.LENGTH(X));
    SHA1_FINISH_CTX(RES);
    RETURN HEXTORAW(TO_CHAR(RES(0),'FM0xxxxxxx') || TO_CHAR(RES(1),'FM0xxxxxxx') || TO_CHAR(RES(2),'FM0xxxxxxx') || TO_CHAR(RES(3),'FM0xxxxxxx') || TO_CHAR(RES(4),'FM0xxxxxxx'));
  END;

  FUNCTION SHA256(X IN RAW) RETURN SHA256_CHECKSUM_RAW AS
    K TA_NUMBER;
    CTX TR_CTX;
    FILLBUF TA_NUMBER; 
    RES TA_NUMBER;

    PROCEDURE SHA256_INIT_K AS
    BEGIN
      K(0)  := TO_NUMBER('428a2f98', 'xxxxxxxx');
      K(1)  := TO_NUMBER('71374491', 'xxxxxxxx');
      K(2)  := TO_NUMBER('b5c0fbcf', 'xxxxxxxx');
      K(3)  := TO_NUMBER('e9b5dba5', 'xxxxxxxx');
      K(4)  := TO_NUMBER('3956c25b', 'xxxxxxxx');
      K(5)  := TO_NUMBER('59f111f1', 'xxxxxxxx');
      K(6)  := TO_NUMBER('923f82a4', 'xxxxxxxx');
      K(7)  := TO_NUMBER('ab1c5ed5', 'xxxxxxxx');
      K(8)  := TO_NUMBER('d807aa98', 'xxxxxxxx');
      K(9)  := TO_NUMBER('12835b01', 'xxxxxxxx');
      K(10) := TO_NUMBER('243185be', 'xxxxxxxx');
      K(11) := TO_NUMBER('550c7dc3', 'xxxxxxxx');
      K(12) := TO_NUMBER('72be5d74', 'xxxxxxxx');
      K(13) := TO_NUMBER('80deb1fe', 'xxxxxxxx');
      K(14) := TO_NUMBER('9bdc06a7', 'xxxxxxxx');
      K(15) := TO_NUMBER('c19bf174', 'xxxxxxxx');
      K(16) := TO_NUMBER('e49b69c1', 'xxxxxxxx');
      K(17) := TO_NUMBER('efbe4786', 'xxxxxxxx');
      K(18) := TO_NUMBER('0fc19dc6', 'xxxxxxxx');
      K(19) := TO_NUMBER('240ca1cc', 'xxxxxxxx');
      K(20) := TO_NUMBER('2de92c6f', 'xxxxxxxx');
      K(21) := TO_NUMBER('4a7484aa', 'xxxxxxxx');
      K(22) := TO_NUMBER('5cb0a9dc', 'xxxxxxxx');
      K(23) := TO_NUMBER('76f988da', 'xxxxxxxx');
      K(24) := TO_NUMBER('983e5152', 'xxxxxxxx');
      K(25) := TO_NUMBER('a831c66d', 'xxxxxxxx');
      K(26) := TO_NUMBER('b00327c8', 'xxxxxxxx');
      K(27) := TO_NUMBER('bf597fc7', 'xxxxxxxx');
      K(28) := TO_NUMBER('c6e00bf3', 'xxxxxxxx');
      K(29) := TO_NUMBER('d5a79147', 'xxxxxxxx');
      K(30) := TO_NUMBER('06ca6351', 'xxxxxxxx');
      K(31) := TO_NUMBER('14292967', 'xxxxxxxx');
      K(32) := TO_NUMBER('27b70a85', 'xxxxxxxx');
      K(33) := TO_NUMBER('2e1b2138', 'xxxxxxxx');
      K(34) := TO_NUMBER('4d2c6dfc', 'xxxxxxxx');
      K(35) := TO_NUMBER('53380d13', 'xxxxxxxx');
      K(36) := TO_NUMBER('650a7354', 'xxxxxxxx');
      K(37) := TO_NUMBER('766a0abb', 'xxxxxxxx');
      K(38) := TO_NUMBER('81c2c92e', 'xxxxxxxx');
      K(39) := TO_NUMBER('92722c85', 'xxxxxxxx');
      K(40) := TO_NUMBER('a2bfe8a1', 'xxxxxxxx');
      K(41) := TO_NUMBER('a81a664b', 'xxxxxxxx');
      K(42) := TO_NUMBER('c24b8b70', 'xxxxxxxx');
      K(43) := TO_NUMBER('c76c51a3', 'xxxxxxxx');
      K(44) := TO_NUMBER('d192e819', 'xxxxxxxx');
      K(45) := TO_NUMBER('d6990624', 'xxxxxxxx');
      K(46) := TO_NUMBER('f40e3585', 'xxxxxxxx');
      K(47) := TO_NUMBER('106aa070', 'xxxxxxxx');
      K(48) := TO_NUMBER('19a4c116', 'xxxxxxxx');
      K(49) := TO_NUMBER('1e376c08', 'xxxxxxxx');
      K(50) := TO_NUMBER('2748774c', 'xxxxxxxx');
      K(51) := TO_NUMBER('34b0bcb5', 'xxxxxxxx');
      K(52) := TO_NUMBER('391c0cb3', 'xxxxxxxx');
      K(53) := TO_NUMBER('4ed8aa4a', 'xxxxxxxx');
      K(54) := TO_NUMBER('5b9cca4f', 'xxxxxxxx');
      K(55) := TO_NUMBER('682e6ff3', 'xxxxxxxx');
      K(56) := TO_NUMBER('748f82ee', 'xxxxxxxx');
      K(57) := TO_NUMBER('78a5636f', 'xxxxxxxx');
      K(58) := TO_NUMBER('84c87814', 'xxxxxxxx');
      K(59) := TO_NUMBER('8cc70208', 'xxxxxxxx');
      K(60) := TO_NUMBER('90befffa', 'xxxxxxxx');
      K(61) := TO_NUMBER('a4506ceb', 'xxxxxxxx');
      K(62) := TO_NUMBER('bef9a3f7', 'xxxxxxxx');
      K(63) := TO_NUMBER('c67178f2', 'xxxxxxxx');

      FILLBUF(0) := BITS_80000000;
      FOR I IN 1..7 LOOP
        FILLBUF(I) := 0;
      END LOOP;
    END;

    PROCEDURE SHA256_INIT_CTX AS
    BEGIN
      CTX.H(0)     := TO_NUMBER('6a09e667', 'xxxxxxxx');
      CTX.H(1)     := TO_NUMBER('bb67ae85', 'xxxxxxxx');
      CTX.H(2)     := TO_NUMBER('3c6ef372', 'xxxxxxxx');
      CTX.H(3)     := TO_NUMBER('a54ff53a', 'xxxxxxxx');
      CTX.H(4)     := TO_NUMBER('510e527f', 'xxxxxxxx');
      CTX.H(5)     := TO_NUMBER('9b05688c', 'xxxxxxxx');
      CTX.H(6)     := TO_NUMBER('1f83d9ab', 'xxxxxxxx');
      CTX.H(7)     := TO_NUMBER('5be0cd19', 'xxxxxxxx');
      CTX.TOTAL(0) := 0;
      CTX.TOTAL(1) := 0;
      CTX.BUFLEN   := 0;
      FOR IDX IN 0..32 LOOP
        CTX.BUFFER32(IDX) := 0;
      END LOOP;
    END;

    PROCEDURE SHA256_PROCESS_BLOCK(BUFFER IN TA_NUMBER, LEN IN NUMBER) AS
      WORDS TA_NUMBER := BUFFER;
      NWORDS    NUMBER   := TRUNC(LEN / 4);
      POS_WORDS NUMBER;
      T         NUMBER;
      A         NUMBER := CTX.H(0);
      B         NUMBER := CTX.H(1);
      C         NUMBER := CTX.H(2);
      D         NUMBER := CTX.H(3);
      E         NUMBER := CTX.H(4);
      F         NUMBER := CTX.H(5);
      G         NUMBER := CTX.H(6);
      H         NUMBER := CTX.H(7);
      W TA_NUMBER; --//[64] ;
      A_SAVE NUMBER;
      B_SAVE NUMBER;
      C_SAVE NUMBER;
      D_SAVE NUMBER;
      E_SAVE NUMBER;
      F_SAVE NUMBER;
      G_SAVE NUMBER;
      H_SAVE NUMBER;
      T1     NUMBER;
      T2     NUMBER;
    BEGIN
      /* First increment the byte count.  FIPS 180-2 specifies the possible length of the file up to 2^64 bits. Here we only compute the number of bytes.  */
      CTX.TOTAL(1) := CTX.TOTAL(1) + LEN;
      /* Process all bytes in the buffer with 64 bytes in each round of the loop.  */
      POS_WORDS := 0;
      WHILE (NWORDS > 0) LOOP
        A_SAVE := A;
        B_SAVE := B;
        C_SAVE := C;
        D_SAVE := D;
        E_SAVE := E;
        F_SAVE := F;
        G_SAVE := G;
        H_SAVE := H;
        /* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
        FOR T IN 0..15 LOOP
          W(T)      := WORDS(POS_WORDS);
          POS_WORDS := POS_WORDS + 1;
        END LOOP;
        FOR T IN 16..63 LOOP
          W(T) := BITAND(OP_R1(W(T-2)) + W(T-7) + OP_R0(W(T-15)) + W(T-16), BITS_FFFFFFFF);
        END LOOP;
        /* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
        FOR T IN 0..63 LOOP
          T1 := BITAND(H        + OP_S1(E) + OP_CH (E, F, G) + K(T) + W(T), BITS_FFFFFFFF);
          T2 := BITAND(OP_S0(A) + OP_MAJ (A, B, C), BITS_FFFFFFFF);
          H  := G;
          G  := F;
          F  := E;
          E  := BITAND(D + T1, BITS_FFFFFFFF);
          D  := C;
          C  := B;
          B  := A;
          A  := BITAND(T1 + T2, BITS_FFFFFFFF);
        END LOOP;
        /* Add the starting values of the context according to FIPS 180-2:6.2.2 step 4.  */
        A := BITAND(A + A_SAVE, BITS_FFFFFFFF);
        B := BITAND(B + B_SAVE, BITS_FFFFFFFF);
        C := BITAND(C + C_SAVE, BITS_FFFFFFFF);
        D := BITAND(D + D_SAVE, BITS_FFFFFFFF);
        E := BITAND(E + E_SAVE, BITS_FFFFFFFF);
        F := BITAND(F + F_SAVE, BITS_FFFFFFFF);
        G := BITAND(G + G_SAVE, BITS_FFFFFFFF);
        H := BITAND(H + H_SAVE, BITS_FFFFFFFF);
        /* Prepare for the next round.  */
        NWORDS := NWORDS - 16;
      END LOOP;
      /* Put checksum in context given as argument.  */
      CTX.H(0) := A;
      CTX.H(1) := B;
      CTX.H(2) := C;
      CTX.H(3) := D;
      CTX.H(4) := E;
      CTX.H(5) := F;
      CTX.H(6) := G;
      CTX.H(7) := H;
    END;

    PROCEDURE SHA256_PROCESS_BYTES(BUFFER IN RAW, LEN IN NUMBER) AS
      LEFT_OVER     NUMBER;
      LEFT_OVER_BLK NUMBER;
      LEFT_OVER_MOD NUMBER;
      ADD           NUMBER;
      T_LEN         NUMBER          := LEN;
      T_BUFFER      RAW(16384) := BUFFER;
      X_BUFFER32 TA_NUMBER;
    BEGIN
      /* When we already have some bits in our internal buffer concatenate both inputs first.  */
      IF (CTX.BUFLEN > 0) THEN
        LEFT_OVER   := CTX.BUFLEN;
        IF 128 - LEFT_OVER > T_LEN THEN
          ADD := T_LEN;
        ELSE
          ADD := 128 - LEFT_OVER;
        END IF;
        FOR IDX IN 1..ADD LOOP
          LEFT_OVER_BLK := TRUNC((LEFT_OVER + IDX - 1)/4);
          LEFT_OVER_MOD := MOD((LEFT_OVER + IDX - 1), 4);
          IF (LEFT_OVER_MOD = 0) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
          ELSIF (LEFT_OVER_MOD = 1) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
          ELSIF (LEFT_OVER_MOD = 2) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
          ELSE
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
          END IF;
        END LOOP;
        CTX.BUFLEN    := CTX.BUFLEN + ADD;
        IF (CTX.BUFLEN > 64) THEN
          SHA256_PROCESS_BLOCK (CTX.BUFFER32, BITAND(CTX.BUFLEN, BITS_FFFFFFC0));
          CTX.BUFLEN := BITAND(CTX.BUFLEN, 63);
          /* The regions in the following copy operation cannot overlap.  */
          /* memcpy (ctx->buffer, ￡|ctx->buffer[(left_over + add) ￡| ~63], ctx->buflen); */
          FOR IDX IN 1..CTX.BUFLEN
          LOOP
            DECLARE
              DEST_POS     NUMBER := IDX           -1;
              DEST_POS_BLK NUMBER := TRUNC(DEST_POS/4);
              DEST_POS_MOD NUMBER := MOD(DEST_POS, 4);
              SRC_POS      NUMBER := BITAND(LEFT_OVER + ADD, BITS_FFFFFFC0)+IDX-1;
              SRC_POS_BLK  NUMBER := TRUNC(SRC_POS    /4);
              SRC_POS_MOD  NUMBER := MOD(SRC_POS, 4);
              BYTE_VALUE   NUMBER;
            BEGIN
              IF (SRC_POS_MOD   =0) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_FF000000)/16777216;
              ELSIF (SRC_POS_MOD=1) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_00FF0000)/65536;
              ELSIF (SRC_POS_MOD=2) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_0000FF00)/256;
              ELSE
                BYTE_VALUE := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_000000FF);
              END IF;
              IF (DEST_POS_MOD              =0) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_00FFFFFF) + BYTE_VALUE*16777216;
              ELSIF (DEST_POS_MOD           =1) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FF00FFFF) + BYTE_VALUE*65536;
              ELSIF (DEST_POS_MOD           =2) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFF00FF) + BYTE_VALUE*256;
              ELSE
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFFFF00) + BYTE_VALUE;
              END IF;
            END;
          END LOOP;
        END IF;
        T_BUFFER := UTL_RAW.SUBSTR(T_BUFFER, ADD+1);
        T_LEN    := T_LEN               - ADD;
      END IF;
      /* Process available complete blocks.  */
      IF (T_LEN >= 64) THEN
        DECLARE
          CNT        NUMBER := BITAND(T_LEN, BITS_FFFFFFC0);
          TARGET_BLK NUMBER;
          TARGET_MOD NUMBER;
        BEGIN
          FOR IDX IN 0..CNT
          LOOP
            X_BUFFER32(IDX) := 0;
          END LOOP;
          FOR IDX IN 1..CNT
          LOOP
            TARGET_BLK               := TRUNC((IDX-1)/4);
            TARGET_MOD               := MOD((IDX  -1), 4);
            IF (TARGET_MOD            =0) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
            ELSIF (TARGET_MOD         =1) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
            ELSIF (TARGET_MOD         =2) THEN
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
            ELSE
              X_BUFFER32(TARGET_BLK) := BITAND(X_BUFFER32(TARGET_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
            END IF;
          END LOOP;
          SHA256_PROCESS_BLOCK (X_BUFFER32, CNT);
          T_BUFFER := UTL_RAW.SUBSTR(T_BUFFER, CNT+1);
        END;
        T_LEN := BITAND(T_LEN, 63);
      END IF;
      /* Move remaining bytes into internal buffer.  */
      IF (T_LEN    > 0) THEN
        LEFT_OVER := CTX.BUFLEN;
        /* memcpy (￡|ctx->buffer[left_over], t_buffer, t_len); */
        FOR IDX IN 1..T_LEN
        LOOP
          LEFT_OVER_BLK                 := TRUNC((LEFT_OVER+IDX-1)/4);
          LEFT_OVER_MOD                 := MOD((LEFT_OVER  +IDX-1), 4);
          IF (LEFT_OVER_MOD              =0) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_00FFFFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*16777216;
          ELSIF (LEFT_OVER_MOD           =1) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FF00FFFF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*65536;
          ELSIF (LEFT_OVER_MOD           =2) THEN
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFF00FF) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1))*256;
          ELSE
            CTX.BUFFER32(LEFT_OVER_BLK) := BITAND(CTX.BUFFER32(LEFT_OVER_BLK),BITS_FFFFFF00) + UTL_RAW.CAST_TO_BINARY_INTEGER(UTL_RAW.SUBSTR(T_BUFFER,IDX,1));
          END IF;
        END LOOP;
        LEFT_OVER     := LEFT_OVER + T_LEN;
        IF (LEFT_OVER >= 64) THEN
          SHA256_PROCESS_BLOCK (CTX.BUFFER32, 64);
          LEFT_OVER := LEFT_OVER - 64;
          /* memcpy (ctx->buffer, ￡|ctx->buffer[64], left_over); */
          FOR IDX IN 1..LEFT_OVER
          LOOP
            DECLARE
              DEST_POS     NUMBER := IDX           -1;
              DEST_POS_BLK NUMBER := TRUNC(DEST_POS/4);
              DEST_POS_MOD NUMBER := MOD(DEST_POS, 4);
              SRC_POS      NUMBER := IDX          +64-1;
              SRC_POS_BLK  NUMBER := TRUNC(SRC_POS/4);
              SRC_POS_MOD  NUMBER := MOD(SRC_POS, 4);
              BYTE_VALUE   NUMBER;
            BEGIN
              IF (SRC_POS_MOD   =0) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_FF000000)/16777216;
              ELSIF (SRC_POS_MOD=1) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_00FF0000)/65536;
              ELSIF (SRC_POS_MOD=2) THEN
                BYTE_VALUE     := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_0000FF00)/256;
              ELSE
                BYTE_VALUE := BITAND(CTX.BUFFER32(SRC_POS_BLK),BITS_000000FF);
              END IF;
              IF (DEST_POS_MOD              =0) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_00FFFFFF) + BYTE_VALUE*16777216;
              ELSIF (DEST_POS_MOD           =1) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FF00FFFF) + BYTE_VALUE*65536;
              ELSIF (DEST_POS_MOD           =2) THEN
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFF00FF) + BYTE_VALUE*256;
              ELSE
                CTX.BUFFER32(DEST_POS_BLK) := BITAND(CTX.BUFFER32(DEST_POS_BLK),BITS_FFFFFF00) + BYTE_VALUE;
              END IF;
            END;
          END LOOP;
        END IF;
        CTX.BUFLEN := LEFT_OVER;
      END IF;
    END;

    PROCEDURE SHA256_FINISH_CTX(RESBUF OUT NOCOPY TA_NUMBER) AS
      BYTES     NUMBER := CTX.BUFLEN;
      PAD       NUMBER;
      PAD_IN    NUMBER;
      PAD_OUT   NUMBER;
      START_IDX NUMBER;
      I         NUMBER;
    BEGIN
      /* Now count remaining bytes.  */
      CTX.TOTAL(1) := CTX.TOTAL(1)+BYTES;
      /* Fill left bytes. */
      IF (BYTES >= 56) THEN
        PAD     := 64 + 56 - BYTES;
      ELSE
        PAD := 56 - BYTES;
      END IF;
      PAD_IN                      := 4     - MOD(BYTES,4);
      PAD_OUT                     := PAD   - PAD_IN;
      START_IDX                   := (BYTES-MOD(BYTES,4))/4;
      IF (PAD_IN                   < 4) THEN
        IF (PAD_IN                 = 1) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FFFFFF00) + BITS_00000080;
        ELSIF (PAD_IN              = 2) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FFFF0000) + BITS_00008000;
        ELSIF (PAD_IN              = 3) THEN
          CTX.BUFFER32(START_IDX) := BITAND(CTX.BUFFER32(START_IDX), BITS_FF000000) + BITS_00800000;
        END IF;
        FOR IDX IN (START_IDX+1)..(START_IDX+1+PAD_OUT/4-1)
        LOOP
          CTX.BUFFER32(IDX) := 0;
        END LOOP;
      ELSE
        FOR IDX IN START_IDX..(START_IDX+PAD/4-1)
        LOOP
          IF (IDX              = START_IDX) THEN
            CTX.BUFFER32(IDX) := BITS_80000000;
          ELSE
            CTX.BUFFER32(IDX) := 0;
          END IF;
        END LOOP;
      END IF;
      /* Put the 64-bit file length in *bits* at the end of the buffer.  */
      CTX.BUFFER32((BYTES                       + PAD + 4) / 4) := BITAND(CTX.TOTAL(1) * 8, BITS_FFFFFFFF);
      CTX.BUFFER32((BYTES                       + PAD) / 4)     := BITOR ( BITAND(CTX.TOTAL(0) * 8, BITS_FFFFFFFF), BITAND(CTX.TOTAL(1) / 536870912, BITS_FFFFFFFF) );
      SHA256_PROCESS_BLOCK (CTX.BUFFER32, BYTES + PAD + 8);
      FOR IDX                                  IN 0..7
      LOOP
        RESBUF(IDX) := CTX.H(IDX);
      END LOOP;
    END;

  BEGIN
    SHA256_INIT_K;
    SHA256_INIT_CTX;
    SHA256_PROCESS_BYTES(X, UTL_RAW.LENGTH(X));
    SHA256_FINISH_CTX(RES);
    RETURN HEXTORAW(TO_CHAR(RES(0),'FM0xxxxxxx') || TO_CHAR(RES(1),'FM0xxxxxxx') || TO_CHAR(RES(2),'FM0xxxxxxx') || TO_CHAR(RES(3),'FM0xxxxxxx') || TO_CHAR(RES(4),'FM0xxxxxxx') || TO_CHAR(RES(5),'FM0xxxxxxx') || TO_CHAR(RES(6),'FM0xxxxxxx') || TO_CHAR(RES(7),'FM0xxxxxxx'));
  END;
  
END HASH;