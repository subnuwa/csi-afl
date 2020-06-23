
#define NUM_EDGE_FILE "num_edges.txt"

#define COND_ADDR_ID "cond_addr_ids.txt"
#define COND_NOT_ADDR_ID "cond_not_addr_id.txt"
#define NO_JUMP_ADDR_ID "no_jump_addr_id.txt"
#define UNCOND_JUMP_ADDR_ID "uncond_jump_addr_id.txt"

#define INDIRECT_ADDR_ID    "indirect_addr_ids.txt"

//mark file for pre-determined edges
#define PATH_MARKS      "path_marks.txt"
// mark file for indirect edges
//#define INDIRECT_MARKS "indirect_marks.txt"

//#define SKIP_BLOCKS     "skip_blocks.txt"

#define BASE_INDIRECT   3
// //bytes for checksum for path id
// #define SIZE_CKSUM_PATH         (1 << 7)
// #define BYTES_CKSUM_PATH        (4 * SIZE_CKSUM_PATH)

//byte for recording the flags of loops
#define FLAG_LOOP   1

// byte for record exit code COND_COVERAGE or INDIRECT_COVERAGE
#define BYTE_EXIT       1

// give loops more air time
#define LOOP_TIME   8


#define COND_COVERAGE 66 //exit(COND_COVERAGE), conditional jump
#define INDIRECT_COVERAGE 67  //indirect jump/call


// for remove exit(); the mapping
#define ORACLE_MAP      "oracle_map_addr.txt"
#define CRASHER_MAP     "crasher_map_addr.txt"
#define ORACLE_EDGES_MAP        "oracle_edges_mapping.txt"
#define CRASHER_EDGES_MAP        "crasher_edges_mapping.txt"

#define EDGE_COVERED    1
#define EDGE_MARK       2
#define EDGE_CRASH      4