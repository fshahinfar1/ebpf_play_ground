enum CLASSES {
    LD,
    LDX,
    ST,
    STX,
    ALU,
    JMP,
    ALU64,
};

enum ALU_OPCODES {
    ADD,
    SUB,
    MUL,
    DIV,
    OR,
    AND,
    LSH,
    RSH,
    NEG,
    MOD,
    XOR,
    MOV,
    ARSH,
    _ENDIAN_,
};

enum JMP_OPCODES {
    JA,
    JEQ,
    JGT,
    JGE,
    JSET,
    JNE,
    JSGT,
    JSGE,
    CALL,
    EXIT,
    JLT,
    JLE,
    JSLT,
    JSLE,
};

enum MODES {
    IMM,
    ABS,
    IND,
    MEM,
    XADD,
};

enum SIZES {
    W,
    H,
    D,
    DW,
};


byte BPF_CLASS_LD = 0;
byte BPF_CLASS_LDX = 1;
byte BPF_CLASS_ST = 2;
byte BPF_CLASS_STX = 3;
byte BPF_CLASS_ALU = 4;
byte BPF_CLASS_JMP = 5;
byte BPF_CLASS_ALU64 = 7;

byte BPF_ALU_NEG = 8;
byte BPF_ALU_END = 13;


class Disassembler {
    private byte[] byte_code;
    Disassembler(byte[] bcode) {
        this.byte_code = bcode;
    }
}