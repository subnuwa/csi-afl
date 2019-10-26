
#define COND_NOT_TAKEN "CondNotTaken.bin"
#define COND_TAKEN "CondTaken.bin"
#define INDIRECT_CALL "indirectCall.bin"
#define INDIRECT_JUMP "indirectJump.bin"

#define ONE_ADDR "oneAddr.bin"
// for path marks
#define MARK_COND_NOT_TAKEN "MARKCondNotTaken.bin"
#define MARK_COND_TAKEN "MARKCondTaken.bin"
#define MARK_INDIRECT_CALL "MARKindirectCall.bin"
#define MARK_INDIRECT_JUMP "MARKindirectJump.bin"

#define MARK_SIZE 8 //size of unsigned long

// #define TYPE_CTAKEN 1  //condition branch taken
// #define TYPE_NCTAKEN 2  //condition branch not taken
// #define TYPE_CALL 3  //indirect call
// #define TYPE_JUMP 4  //indirect jump

enum branType{
/*00*/ TYPE_CTAKEN,  //condition branch taken
/*01*/ TYPE_NCTAKEN,  //condition branch not taken
/*02*/ TYPE_CALL,  //indirect call
/*03*/ TYPE_JUMP  //indirect jump
};

#define COND_COVERAGE 66 //exit(COND_COVERAGE), conditional jump
#define INDIRECT_COVERAGE 67  //indirect jump/call


enum Category {
    /*00*/ BIN_NONE,
    /*01*/ BIN_CRASH,  //instrument crash binary
    /*02*/ BIN_TRACER,  //instrument tracer binary
    /*03*/ BIN_ORACLE,  // instrument oracle binary
    /*04*/ BIN_TRIMMER  // instrument trimmer binary
};