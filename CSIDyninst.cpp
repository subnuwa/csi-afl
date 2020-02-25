/*
TODO:
1. first, assign ids to conditonal edges, and save (addr1, addr2, id) to a file;
    two files: condition-taken addrs, and condition-not-taken addrs;
    this ensures the ids are assigned identically;
2. instrument oracle
3. instrument tracer
*/

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cmath>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cstddef>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include "config.h"
#include "types.h"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

#include <map>
#include <sstream>
#include <climits>
#include <set>
using namespace std;

#include "instConfig.h"
#include "instUnmap.h"
// DyninstAPI includes
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"


using namespace Dyninst;

//hash table length
//condition_id = 0; // assign  for each conditional edges
static u32 num_predtm = 0, // the number of total pre-determined edges; unique id
    num_indirect = 0,   // the number of total indirect edges
    max_map_size = 0; // the number of all edges, including potential indirect edges



//cmd line options
char *originalBinary;
char *instrumentedBinary;
bool verbose = false;
char* csifuzz_dir = NULL;  //Output dir of csifuzz results

bool isPrep = false, // preprocessing
    isOracle = false, // instrument oracle
    isTrimmer = false, // trimmer
    isTracer = false; // instrument tracer

std::unordered_map<EDGE, u32, HashEdge> cond_map;
std::unordered_map<EDGE, u32, HashEdge> condnot_map;
std::unordered_map<EDGE, u32, HashEdge> uncond_map;
std::unordered_map<EDGE, u32, HashEdge> nojump_map;


// call back functions
BPatch_function *OraclePredtm;
BPatch_function *OracleIndirect;
BPatch_function *initAflForkServer;
BPatch_function *TracerPredtm;
BPatch_function *TracerIndirect;
BPatch_function *TrimmerIndirect;
BPatch_function *TracerLoops;
BPatch_function *TrimmerPredtm;

const char *instLibrary = "./libCSIDyninst.so";

static const char *OPT_STR = "i:o:vb:PFTM";
static const char *USAGE = " -i <binary> -o <binary> -b <csifuzz-dir> -F(PT)\n \
            -i: Input binary \n \
            -o: Output binary\n \
            -b: Output dir of csifuzz results\n \
            -v: Verbose output\n \
            -P: The initial preprocessing (counting edges and blocks; writing address files.)\n \
            -F: The full-speed oracle\n \
            -T: The tracer\n \
            -M: The trimmer\n";

bool parseOptions(int argc, char **argv)
{

    int c;
    while ((c = getopt (argc, argv, OPT_STR)) != -1) {
        switch ((char) c) {
        case 'i':
            originalBinary = optarg;
            break;
        case 'o':
            instrumentedBinary = optarg;
            break;
        case 'b':
            csifuzz_dir = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'P':
            isPrep = true;
            break;
        case 'F':
            isOracle = true;
            break;
        case 'T':
            isTracer = true;
            break;
        case 'M':
            isTrimmer = true;
            break;
        default:
            cerr << "Usage: " << argv[0] << USAGE;
            return false;
        }
    }

    if(originalBinary == NULL) {
        cerr << "Input binary is required!"<< endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if((instrumentedBinary == NULL) && (isPrep == false)) {
        cerr << "Output binary or -P is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(csifuzz_dir == NULL){
        cerr << "Output directory for csifuzz is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if ((isPrep == false) && (isOracle == false) && (isTracer == false) && (isTrimmer == false)){
        cerr << "Specify -P, -T, -F, or -M" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    return true;
}

BPatch_function *findFuncByName (BPatch_image * appImage, char *funcName)
{
    BPatch_Vector < BPatch_function * >funcs;

    if (NULL == appImage->findFunction (funcName, funcs) || !funcs.size ()
        || NULL == funcs[0]) {
        cerr << "Failed to find " << funcName << " function." << endl;
        return NULL;
    }

    return funcs[0];
}

//skip some functions
bool isSkipFuncs(char* funcName){
    if (string(funcName) == string("first_init") ||
        string(funcName) == string("__mach_init") ||
        string(funcName) == string("_hurd_init") ||
        string(funcName) == string("_hurd_preinit_hook") ||
        string(funcName) == string("doinit") ||
        string(funcName) == string("doinit1") ||
        string(funcName) == string("init") ||
        string(funcName) == string("init1") ||
        string(funcName) == string("_hurd_subinit") ||
        string(funcName) == string("init_dtable") ||
        string(funcName) == string("_start1") ||
        string(funcName) == string("preinit_array_start") ||
        string(funcName) == string("_init") ||
        string(funcName) == string("init") ||
        string(funcName) == string("fini") ||
        string(funcName) == string("_fini") ||
        string(funcName) == string("_hurd_stack_setup") ||
        string(funcName) == string("_hurd_startup") ||
        string(funcName) == string("register_tm_clones") ||
        string(funcName) == string("deregister_tm_clones") ||
        string(funcName) == string("frame_dummy") ||
        string(funcName) == string("__do_global_ctors_aux") ||
        string(funcName) == string("__do_global_dtors_aux") ||
        string(funcName) == string("__libc_csu_init") ||
        string(funcName) == string("__libc_csu_fini") ||
        string(funcName) == string("start") ||
        string(funcName) == string("_start") || 
        string(funcName) == string("__libc_start_main") ||
        string(funcName) == string("__gmon_start__") ||
        string(funcName) == string("__cxa_atexit") ||
        string(funcName) == string("__cxa_finalize") ||
        string(funcName) == string("__assert_fail") ||
        string(funcName) == string("_dl_start") || 
        string(funcName) == string("_dl_start_final") ||
        string(funcName) == string("_dl_sysdep_start") ||
        string(funcName) == string("dl_main") ||
        string(funcName) == string("_dl_allocate_tls_init") ||
        string(funcName) == string("_dl_start_user") ||
        string(funcName) == string("_dl_init_first") ||
        string(funcName) == string("_dl_init")) {
        return true; //skip these functions
        }
    return false;    
}


//count the number of indirect and conditaional edges
bool count_edges(BPatch_binaryEdit * appBin, BPatch_image *appImage, 
                    vector < BPatch_function * >::iterator funcIter, 
                    char* funcName, fs::path output_dir){
    fs::path cond_addr_ids = output_dir / COND_ADDR_ID; // out_dir: csifuzz outputs;
    fs::path condnot_addr_ids = output_dir / COND_NOT_ADDR_ID;
    fs::path nojump_addr_ids = output_dir / NO_JUMP_ADDR_ID; // edges without jumps
    fs::path unjump_addr_ids = output_dir / UNCOND_JUMP_ADDR_ID; // unconditional jumps

    BPatch_function *curFunc = *funcIter;
    BPatch_flowGraph *appCFG = curFunc->getCFG ();

    BPatch_Set < BPatch_basicBlock * > allBlocks;
    if (!appCFG->getAllBasicBlocks (allBlocks)) {
        cerr << "Failed to find basic blocks for function " << funcName << endl;
        return false;
    } else if (allBlocks.size () == 0) {
        cerr << "No basic blocks for function " << funcName << endl;
        return false;
    }

    ofstream CondTaken_file, CondNot_file, NoJump_file, UncondJump_file;
    CondTaken_file.open (cond_addr_ids.c_str(), ios::out | ios::app | ios::binary); //write file
    CondNot_file.open (condnot_addr_ids.c_str(), ios::out | ios::app | ios::binary); //write file
    NoJump_file.open (nojump_addr_ids.c_str(), ios::out | ios::app | ios::binary); //write file
    UncondJump_file.open (unjump_addr_ids.c_str(), ios::out | ios::app | ios::binary); //write file

    set < BPatch_basicBlock *>::iterator bb_iter;
    BPatch_basicBlock *src_bb = NULL;
    BPatch_basicBlock *trg_bb = NULL;
    unsigned long src_addr = 0;
    unsigned long trg_addr = 0;

    for (bb_iter = allBlocks.begin (); bb_iter != allBlocks.end (); bb_iter++){
        BPatch_basicBlock * block = *bb_iter;
        vector<pair<Dyninst::InstructionAPI::Instruction, Dyninst::Address> > insns;
        block->getInstructions(insns);

        //Dyninst::Address addr = insns.back().second;  //addr: equal to offset when it's binary rewrite
        Dyninst::InstructionAPI::Instruction insn = insns.back().first; 
        Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

        //conditional jumps
        vector<BPatch_edge *> outgoingEdge;
        block->getOutgoingEdges(outgoingEdge);
        vector<BPatch_edge *>::iterator edge_iter;

        
        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            src_bb = (*edge_iter)->getSource();
            trg_bb = (*edge_iter)->getTarget();
            src_addr = src_bb->getStartAddress();
            trg_addr = trg_bb->getStartAddress();
            //count pre-determined edges
            if ((*edge_iter)->getType() == CondJumpTaken){

                if(CondTaken_file.is_open()){
                    CondTaken_file << src_addr << " " << trg_addr << " " << num_predtm << endl; 
                    
                }
                else{
                    cout << "cannot open the file: " << cond_addr_ids.c_str() << endl;
                    return false;
                }
                num_predtm++;
            }
            else if ((*edge_iter)->getType() == CondJumpNottaken){
                if(CondNot_file.is_open()){
                    CondNot_file << src_addr << " " << trg_addr << " " << num_predtm << endl; 
                    
                }
                else{
                    cout << "cannot open the file: " << condnot_addr_ids.c_str() << endl;
                    return false;
                }
                num_predtm++;
            }
            else if ((*edge_iter)->getType() == UncondJump){
                if(UncondJump_file.is_open()){
                    UncondJump_file << src_addr << " " << trg_addr << " " << num_predtm << endl; 
                    
                }
                else{
                    cout << "cannot open the file: " << unjump_addr_ids.c_str() << endl;
                    return false;
                }
                num_predtm++;
            }
            else if ((*edge_iter)->getType() == NonJump){
                if(NoJump_file.is_open()){
                    NoJump_file << src_addr << " " << trg_addr << " " << num_predtm << endl; 
                    
                }
                else{
                    cout << "cannot open the file: " << nojump_addr_ids.c_str() << endl;
                    return false;
                }
               num_predtm++;
            }         
            
        }

        //indirect edges
        for(Dyninst::InstructionAPI::Instruction::cftConstIter iter = insn.cft_begin(); iter != insn.cft_end(); ++iter) {
            if(iter->isIndirect) {
                
                if(category == Dyninst::InstructionAPI::c_CallInsn) {//indirect call
                    num_indirect++;
                }
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {//indirect jump
                    num_indirect++;
                }
                else if(category == Dyninst::InstructionAPI::c_ReturnInsn) {
                    num_indirect++;
                }
 
            }
        }

    }

    CondTaken_file.close();
    CondNot_file.close();
    NoJump_file.close();
    UncondJump_file.close();

    return true;
    
}

// read addresses and ids from files; ensure that Oracle and Tracer has the same ids
bool readAddrs(fs::path output_dir){
    fs::path cond_addr_ids = output_dir / COND_ADDR_ID; // condition taken;
    fs::path condnot_addr_ids = output_dir / COND_NOT_ADDR_ID; //condition not taken
    fs::path nojump_addr_ids = output_dir / NO_JUMP_ADDR_ID; // edges without jumps
    fs::path unjump_addr_ids = output_dir / UNCOND_JUMP_ADDR_ID; // unconditional jumps

    ifstream CondTaken_file, CondNot_file, NoJump_file, UncondJump_file;
    
    /*recover addresses, ids*/
    struct stat inbuff;
    u64 src_addr, trg_addr;
    u32 edge_id;
    /*     condition taken edges   */
    if (stat(cond_addr_ids.c_str(), &inbuff) == 0){ // file  exists
        CondTaken_file.open (cond_addr_ids.c_str()); //read file
        if (CondTaken_file.is_open()){
            while (CondTaken_file >> src_addr >> trg_addr >> edge_id){
                cond_map.insert(make_pair(EDGE(src_addr, trg_addr), edge_id));
            }
            CondTaken_file.close();
        }

    }
    else{
        cout << "Please create address-ids first." <<endl;
        return false;
    }

    /*     condition not taken edges   */
    if (stat(condnot_addr_ids.c_str(), &inbuff) == 0){ // file  exists
        CondNot_file.open (condnot_addr_ids.c_str()); //read file
        if (CondNot_file.is_open()){
            while (CondNot_file >> src_addr >> trg_addr >> edge_id){
                condnot_map.insert(make_pair(EDGE(src_addr, trg_addr), edge_id));
            }
            CondNot_file.close();
        }

    }
    else{
        cout << "Please create address-ids first." <<endl;
        return false;
    }

    /*    unconditional jumps  */
    if (stat(unjump_addr_ids.c_str(), &inbuff) == 0){ // file  exists
        UncondJump_file.open (unjump_addr_ids.c_str()); //read file
        if (UncondJump_file.is_open()){
            while (UncondJump_file >> src_addr >> trg_addr >> edge_id){
                uncond_map.insert(make_pair(EDGE(src_addr, trg_addr), edge_id));
            }
            UncondJump_file.close();
        }

    }
    else{
        cout << "Please create address-ids first." <<endl;
        return false;
    }

    /*    no jumps  */
    if (stat(nojump_addr_ids.c_str(), &inbuff) == 0){ // file  exists
        NoJump_file.open (nojump_addr_ids.c_str()); //read file
        if (NoJump_file.is_open()){
            while (NoJump_file >> src_addr >> trg_addr >> edge_id){
                nojump_map.insert(make_pair(EDGE(src_addr, trg_addr), edge_id));
            }
            NoJump_file.close();
        }

    }
    else{
        cout << "Please create address-ids first." <<endl;
        return false;
    }

    /* the number of pre-determined edges, map_size */
    fs::path num_file = output_dir / NUM_EDGE_FILE;
    ifstream NunFile;
    if (stat(num_file.c_str(), &inbuff) == 0){ // file  exists
        NunFile.open (num_file.c_str()); //read file
        if (NunFile.is_open()){
            NunFile >> max_map_size >> num_predtm;
            NunFile.close();
        }

    }
    else{
        cout << "Please create num_edges.txt first." <<endl;
        return false;
    }

    return true;

}

// instrument at pre-determined edges
bool instOraclePredtm(BPatch_binaryEdit * appBin, BPatch_function * instFunc, BPatch_point * instrumentPoint, 
                        u32 cond_id, fs::path file_marks){
    vector<BPatch_snippet *> cond_args;
    BPatch_constExpr CondID(cond_id);
    cond_args.push_back(&CondID);
    BPatch_constExpr PathMarks(file_marks.c_str());
    cond_args.push_back(&PathMarks);

    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at id: " << cond_id << endl;
            return false;
        }
    return true;         

}


// instrument at pre-determined edges
bool instTracerPredtm(BPatch_binaryEdit * appBin, BPatch_function * instFunc, BPatch_point * instrumentPoint, 
                        u32 cond_id){
    vector<BPatch_snippet *> cond_args;
    BPatch_constExpr CondID(cond_id);
    cond_args.push_back(&CondID);

    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at id: " << cond_id << endl;
            return false;
        }
    return true;         

}


// instrument at pre-determined edges
bool instTrimmerPredtm(BPatch_binaryEdit * appBin, BPatch_function * instFunc, BPatch_point * instrumentPoint, 
                        u32 cond_id){
    vector<BPatch_snippet *> cond_args;
    BPatch_constExpr CondID(cond_id);
    cond_args.push_back(&CondID);

    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at id: " << cond_id << endl;
            return false;
        }
    return true;         

}

/*
num_all_edges: the number of all edges
num_predtm_edges: the number of all conditional edges
ind_addr_file: path to the file that contains (src_addr des_addr id)
*/
bool instOracleIndirect(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, Dyninst::Address src_addr, u32 num_all_edges, u32 num_predtm_edges,
                fs::path ind_addr_file, fs::path file_marks){
    vector<BPatch_snippet *> ind_args;

    BPatch_constExpr srcOffset((u64)src_addr);
    ind_args.push_back(&srcOffset);
    ind_args.push_back(new BPatch_dynamicTargetExpr());//target offset
    BPatch_constExpr AllEdges(num_all_edges);
    ind_args.push_back(&AllEdges);
    BPatch_constExpr CondEdges(num_predtm_edges);
    ind_args.push_back(&CondEdges);
    BPatch_constExpr AddrIDFile(ind_addr_file.c_str());
    ind_args.push_back(&AddrIDFile);
    BPatch_constExpr MarksFile(file_marks.c_str());
    ind_args.push_back(&MarksFile);


    BPatch_funcCallExpr instIndirect(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instIndirect, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;

}


/*
num_all_edges: the number of all edges
num_predtm_edges: the number of all conditional edges
ind_addr_file: path to the file that contains (src_addr des_addr id)
*/
bool instTracerIndirect(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, Dyninst::Address src_addr, u32 num_all_edges, u32 num_predtm_edges,
                fs::path ind_addr_file){
    vector<BPatch_snippet *> ind_args;

    BPatch_constExpr srcOffset((u64)src_addr);
    ind_args.push_back(&srcOffset);
    ind_args.push_back(new BPatch_dynamicTargetExpr());//target offset
    BPatch_constExpr AllEdges(num_all_edges);
    ind_args.push_back(&AllEdges);
    BPatch_constExpr CondEdges(num_predtm_edges);
    ind_args.push_back(&CondEdges);
    BPatch_constExpr AddrIDFile(ind_addr_file.c_str());
    ind_args.push_back(&AddrIDFile);


    BPatch_funcCallExpr instIndirect(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instIndirect, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;

}

/*
Do AFL stuff 
*/
bool instTrimmerIndirect(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, Dyninst::Address src_addr){
    vector<BPatch_snippet *> ind_args;

    BPatch_constExpr srcOffset((u64)src_addr);
    ind_args.push_back(&srcOffset);
    ind_args.push_back(new BPatch_dynamicTargetExpr());//target offset
    

    BPatch_funcCallExpr instIndirect(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instIndirect, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;

}

/*for loops: instrument at back edges */
bool instLoops(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint){
    vector<BPatch_snippet *> loop_args;

    BPatch_funcCallExpr instLoop(*instFunc, loop_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instLoop, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention for loop." << endl;
            return false;
        }
    return true;
}


/*instrument at edges for one function
    indirect_addrs: path to the file that contains (src_addr des_addr id)
*/
bool edgeInstrument(BPatch_binaryEdit * appBin, BPatch_image *appImage, 
                    vector < BPatch_function * >::iterator funcIter, char* funcName,
                    fs::path output_dir){
    
    BPatch_basicBlock *src_bb = NULL;
    BPatch_basicBlock *trg_bb = NULL;
    unsigned long src_addr = 0;
    unsigned long trg_addr = 0;
    u32 edge_id = 0;

    fs::path path_marks = output_dir / PATH_MARKS; // path to file recording marks in a program
    fs::path indirect_addrs = output_dir / INDIRECT_ADDR_ID; //indirect edge addrs and ids
    BPatch_function *curFunc = *funcIter;
    BPatch_flowGraph *appCFG = curFunc->getCFG ();

    BPatch_Set < BPatch_basicBlock * > allBlocks;
    if (!appCFG->getAllBasicBlocks (allBlocks)) {
        cerr << "Failed to find basic blocks for function " << funcName << endl;
        return false;
    } else if (allBlocks.size () == 0) {
        cerr << "No basic blocks for function " << funcName << endl;
        return false;
    }

    set < BPatch_basicBlock *>::iterator bb_iter;
    for (bb_iter = allBlocks.begin (); bb_iter != allBlocks.end (); bb_iter++){
        BPatch_basicBlock * block = *bb_iter;
        vector<pair<Dyninst::InstructionAPI::Instruction, Dyninst::Address> > insns;
        block->getInstructions(insns);

        Dyninst::Address addr = insns.back().second;  //addr: equal to offset when it's binary rewrite
        Dyninst::InstructionAPI::Instruction insn = insns.back().first; 
        Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

        //conditional jumps
        vector<BPatch_edge *> outgoingEdge;
        (*bb_iter)->getOutgoingEdges(outgoingEdge);
        vector<BPatch_edge *>::iterator edge_iter;

        std::unordered_map<EDGE, u32, HashEdge>::iterator itdl;

        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            src_bb = (*edge_iter)->getSource();
            trg_bb = (*edge_iter)->getTarget();
            src_addr = src_bb->getStartAddress();
            trg_addr = trg_bb->getStartAddress();

            if ((*edge_iter)->getType() == CondJumpTaken){
                itdl = cond_map.find(EDGE(src_addr, trg_addr));
                if (itdl != cond_map.end()){
                    edge_id = (*itdl).second;
                }
                else {
                    cout << "CondJumpTaken could't find an edge at address: " << src_addr << ", " << trg_addr << endl;
                    return false;
                }

                if (isOracle){
                    if (!instOraclePredtm(appBin, OraclePredtm, (*edge_iter)->getPoint(), edge_id, path_marks))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTracer){
                    if (!instTracerPredtm(appBin, TracerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTrimmer){
                    if (!instTrimmerPredtm(appBin, TrimmerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                    
                }
                
            }
            else if ((*edge_iter)->getType() == CondJumpNottaken){
                itdl = condnot_map.find(EDGE(src_addr, trg_addr));
                if (itdl != condnot_map.end()){
                    edge_id = (*itdl).second;
                }
                else {
                    cout << "CondJumpNottaken could't find an edge at address: " << src_addr << ", " << trg_addr << endl;
                    return false;
                }

                if (isOracle){
                    if (!instOraclePredtm(appBin, OraclePredtm, (*edge_iter)->getPoint(), edge_id, path_marks))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTracer){
                    if (!instTracerPredtm(appBin, TracerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTrimmer){
                    if (!instTrimmerPredtm(appBin, TrimmerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                    
                }
                
            } 
            else if ((*edge_iter)->getType() == UncondJump){
                itdl = uncond_map.find(EDGE(src_addr, trg_addr));
                if (itdl != uncond_map.end()){
                    edge_id = (*itdl).second;
                }
                else {
                    cout << "UncondJump could't find an edge at address: " << src_addr << ", " << trg_addr << endl;
                    return false;
                }

                if (isOracle){
                    if (!instOraclePredtm(appBin, OraclePredtm, (*edge_iter)->getPoint(), edge_id, path_marks))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTracer){
                    if (!instTracerPredtm(appBin, TracerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTrimmer){
                    if (!instTrimmerPredtm(appBin, TrimmerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                    
                }
            }
            else if ((*edge_iter)->getType() == NonJump){
                itdl = nojump_map.find(EDGE(src_addr, trg_addr));
                if (itdl != nojump_map.end()){
                    edge_id = (*itdl).second;
                }
                else {
                    cout << "NonJump could't find an edge at address: " << src_addr << ", " << trg_addr << endl;
                    return false;
                }

                if (isOracle){
                    if (!instOraclePredtm(appBin, OraclePredtm, (*edge_iter)->getPoint(), edge_id, path_marks))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTracer){
                    if (!instTracerPredtm(appBin, TracerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                }
                else if (isTrimmer){
                    if (!instTrimmerPredtm(appBin, TrimmerPredtm, (*edge_iter)->getPoint(), edge_id))
                        cout << "Pre-determined edges instrument error." << endl;
                    
                }
                
            }              
            
        }

        //indirect edges
        for(Dyninst::InstructionAPI::Instruction::cftConstIter iter = insn.cft_begin(); iter != insn.cft_end(); ++iter) {
            if(iter->isIndirect) {
                
                if(category == Dyninst::InstructionAPI::c_CallInsn) {//indirect call
                    vector<BPatch_point *> callPoints;
                    appImage->findPoints(addr, callPoints);

                    if (isOracle){
                        if (!instOracleIndirect(appBin, OracleIndirect, callPoints[0], addr, max_map_size, num_predtm, indirect_addrs, path_marks))
                                cout << "Indirect instrument error." << endl;
                    }
                    else if (isTracer){
                        if (!instTracerIndirect(appBin, TracerIndirect, callPoints[0], addr, max_map_size, num_predtm, indirect_addrs))
                                cout << "Indirect instrument error." << endl;
                    }
                    else if (isTrimmer){
                        if (!instTrimmerIndirect(appBin, TrimmerIndirect, callPoints[0], addr))
                                cout << "Indirect instrument error." << endl;
                    }
                    
                    // vector<BPatch_point *>::iterator callPt_iter;
                    // for(callPt_iter = callPoints.begin(); callPt_iter != callPoints.end(); ++callPt_iter) {
                        
                    //     instOracleIndirect(appBin, OracleIndirect, *callPt_iter, addr, max_map_size, num_predtm, indirect_addrs);                       
                    // }
                    
                }
                
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {//indirect jump
                    vector<BPatch_point *> jmpPoints;
                    appImage->findPoints(addr, jmpPoints);
                    
                    if (isOracle){
                        if (!instOracleIndirect(appBin, OracleIndirect, jmpPoints[0], addr, max_map_size, num_predtm, indirect_addrs, path_marks))
                            cout << "Indirect instrument error." << endl;
                    }
                    else if (isTracer){
                        if (!instTracerIndirect(appBin, TracerIndirect, jmpPoints[0], addr, max_map_size, num_predtm, indirect_addrs))
                                cout << "Indirect instrument error." << endl;
                    }
                    else if (isTrimmer){
                        if (!instTrimmerIndirect(appBin, TrimmerIndirect, jmpPoints[0], addr))
                                cout << "Indirect instrument error." << endl;
                    }
                    
                    // vector<BPatch_point *>::iterator jmpPt_iter;
                    // for(jmpPt_iter = jmpPoints.begin(); jmpPt_iter != jmpPoints.end(); ++jmpPt_iter) {
                    //     instOracleIndirect(appBin, OracleIndirect, *jmpPt_iter, addr, max_map_size, num_predtm, indirect_addrs);
                    // }
                }
                // 
                else if(category == Dyninst::InstructionAPI::c_ReturnInsn) {
                    vector<BPatch_point *> retPoints;
                    appImage->findPoints(addr, retPoints);

                    if (isOracle){
                        if (!instOracleIndirect(appBin, OracleIndirect, retPoints[0], addr, max_map_size, num_predtm, indirect_addrs, path_marks))
                                cout << "Indirect instrument error." << endl;
                    }
                    else if (isTracer){
                        if (!instTracerIndirect(appBin, TracerIndirect, retPoints[0], addr, max_map_size, num_predtm, indirect_addrs))
                                cout << "Indirect instrument error." << endl;
                    }
                    else if (isTrimmer){
                        if (!instTrimmerIndirect(appBin, TrimmerIndirect, retPoints[0], addr))
                                cout << "Indirect instrument error." << endl;
                    }
                    
                    // vector<BPatch_point *>::iterator retPt_iter;
                    // for(retPt_iter = retPoints.begin(); retPt_iter != retPoints.end(); ++retPt_iter) {
                    //      if (instOracleIndirect(appBin, OracleIndirect, *retPt_iter, addr, max_map_size, num_predtm, indirect_addrs, path_marks))
                    //             cout << "Indirect instrument error." << endl;
                    // }
                }
 
            }
        }
    }

    if (isTracer){
        /* instrument at loops, in tracer */
        std::vector< BPatch_basicBlockLoop* > allLoops;
        appCFG->getLoops(allLoops);

        if (allLoops.size () != 0) {
            for (auto loop_iter = allLoops.begin(); loop_iter != allLoops.end(); ++ loop_iter){
                std::vector<BPatch_edge *> back_edges;
                (*loop_iter)->getBackEdges(back_edges);
                if (!instLoops(appBin, TracerLoops, back_edges[0]->getPoint())) cout << "Instrument loops failed"<<endl;
            }
        }
    }
    
    return true;
}

/* insert forkserver at the beginning of main
    funcInit: function to be instrumented, i.e., main

*/

bool insertForkServer(BPatch_binaryEdit * appBin, BPatch_function * instIncFunc,
                         BPatch_function *funcInit, u32 num_predtm_edges, fs::path marks_file, fs::path ind_addr_file){

    /* Find the instrumentation points */
    vector < BPatch_point * >*funcEntry = funcInit->findPoint (BPatch_entry);

    if (NULL == funcEntry) {
        cerr << "Failed to find entry for function. " <<  endl;
        return false;
    }

    //cout << "Inserting init callback." << endl;
    BPatch_Vector < BPatch_snippet * >instArgs; 
    BPatch_constExpr NumCond(num_predtm_edges);
    instArgs.push_back(&NumCond);
    
    BPatch_constExpr MARKIDFile(marks_file.c_str());
    instArgs.push_back(&MARKIDFile);
    BPatch_constExpr AddrIDFile(ind_addr_file.c_str());
    instArgs.push_back(&AddrIDFile);

    BPatch_funcCallExpr instIncExpr(*instIncFunc, instArgs);

    /* Insert the snippet at function entry */
    BPatchSnippetHandle *handle =
        appBin->insertSnippet (instIncExpr, *funcEntry, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
        cerr << "Failed to insert init callback." << endl;
        return false;
    }
    return true;
}

int main (int argc, char **argv){

     if(!parseOptions(argc,argv)) {
        return EXIT_FAILURE;
    }

    fs::path out_dir (reinterpret_cast<const char*>(csifuzz_dir)); // files for csifuzz results
    
    fs::path indi_addr_id_file = out_dir / INDIRECT_ADDR_ID; //indirect edge addrs and ids
    fs::path marks_file = out_dir / PATH_MARKS;

    /* start instrumentation*/
    BPatch bpatch;
    // skip all libraries unless -l is set
    BPatch_binaryEdit *appBin = bpatch.openBinary (originalBinary, false);
    if (appBin == NULL) {
        cerr << "Failed to open binary" << endl;
        return EXIT_FAILURE;
    }


    BPatch_image *appImage = appBin->getImage ();

    
    vector < BPatch_function * > allFunctions;
    appImage->getProcedures(allFunctions);

    if (!appBin->loadLibrary (instLibrary)) {
        cerr << "Failed to open instrumentation library " << instLibrary << endl;
        cerr << "It needs to be located in the current working directory." << endl;
        return EXIT_FAILURE;
    }

    initAflForkServer = findFuncByName (appImage, (char *) "initAflForkServer");
 
    //conditional jumps
    OraclePredtm = findFuncByName (appImage, (char *) "OraclePredtm");
    OracleIndirect = findFuncByName (appImage, (char *) "OracleIndirect");
    TracerPredtm = findFuncByName (appImage, (char *) "TracerPredtm");
    TracerIndirect = findFuncByName (appImage, (char *) "TracerIndirect");
    TrimmerIndirect = findFuncByName (appImage, (char *) "TrimmerIndirect");
    TracerLoops = findFuncByName (appImage, (char *) "TracerLoops");
    TrimmerPredtm = findFuncByName (appImage, (char *) "TrimmerPredtm");
    //BBCallback =  findFuncByName (appImage, (char *) "BBCallback");
    //ConditionMark = findFuncByName (appImage, (char *) "ConditionMark");
    
    //atMainExit = findFuncByName (appImage, (char *) "atMainExit");


    if (!initAflForkServer || !OraclePredtm || !OracleIndirect
         || !TracerPredtm || !TracerIndirect || !TracerLoops 
         || !TrimmerPredtm || !TrimmerIndirect) {
        cerr << "Instrumentation library lacks callbacks!" << endl;
        return EXIT_FAILURE;
    }


    /* count the number of edges for the length of hash table
    1. num_c = the number of conditional edges
    2. num_i = the number of indirect call/jump sites
    3. length of hash table = num_c + num_i
    */
   if (isPrep){
       fs::path num_file = out_dir / NUM_EDGE_FILE; // out_dir: csifuzz outputs; max edges
       // iterate over all functions to count edges
        num_predtm = 0;
        num_indirect = 0;
        max_map_size = 0;
        for (auto countIter = allFunctions.begin (); countIter != allFunctions.end (); ++countIter) {
            BPatch_function *countFunc = *countIter;
            char funcName[1024];
            countFunc->getName (funcName, 1024);
            
            if(isSkipFuncs(funcName)) continue;
            //count edges
            if(!count_edges(appBin, appImage, countIter, funcName, out_dir)) 
                                cout << "Empty function" << funcName << endl;      
        }

        // fuzzer gets the number of edges by saved file
        
        u32 num_tpm = num_predtm + num_indirect * BASE_INDIRECT;
        u16 num_exp = (u16)ceil( log(num_tpm) / log(2) );
        // be general with the shared memory
        if(num_exp < MAP_SIZE_POW2) num_exp = MAP_SIZE_POW2;


        max_map_size = (1 << num_exp);
        
        ofstream numedges;
        numedges.open (num_file.c_str(), ios::out | ios::app | ios::binary); //write file
        if(numedges.is_open()){
            numedges << max_map_size << " " << num_predtm << endl; 
            //numedges << num_indirect << endl;
        }
        numedges.close();    
        //TODO: fuzzer gets the values through pipe (or shared memory?)?
        return EXIT_SUCCESS; 
   }
   
   // read address-ids from files
    if(!readAddrs(out_dir)) {
        cout << "Fail to read addresses." << endl;
        return EXIT_FAILURE;
    }

   /* instrument edges
   1. insert at conditional edges, like afl
   2.  insert at indirect edges, and compare edges dynamically:
        1) the first id of an indirect edge is the number of conditional edges num_c
        2) use map to maintain [(src_addr, des_addr), id]
        3) at the beginning of main, insert a global map to load [(src_addr, des_addr), id]
        4) at each indirect edge, when meeting a new indirect edge, write the [(src_addr, des_addr), id] 
            into a file to record them; it can be reused if fuzzing stops accidently
    */
    vector < BPatch_function * >::iterator funcIter;
    for (funcIter = allFunctions.begin (); funcIter != allFunctions.end (); ++funcIter) {
        BPatch_function *curFunc = *funcIter;
        char funcName[1024];
        curFunc->getName (funcName, 1024);
        if(isSkipFuncs(funcName)) continue;
        //instrument at edges
        if (!edgeInstrument(appBin, appImage, funcIter, funcName, out_dir)) {
            cout << "fail to instrument function: " << funcName << endl;
            // return EXIT_FAILURE;
            }

    }

    BPatch_function *funcToPatch = NULL;
    BPatch_Vector<BPatch_function*> funcs;
    
    appImage->findFunction("main",funcs);
    if(!funcs.size()) {
        cerr << "Couldn't locate main, check your binary. "<< endl;
        return EXIT_FAILURE;
    }
    // there should really be only one
    funcToPatch = funcs[0];

    if(!insertForkServer (appBin, initAflForkServer, funcToPatch, num_predtm, marks_file, indi_addr_id_file)){
        cerr << "Could not insert init callback at main." << endl;
        return EXIT_FAILURE;
    }

    if(verbose){
        cout << "Saving the instrumented binary to " << instrumentedBinary << "..." << endl;
    }
    // save the instrumented binary
    if (!appBin->writeFile (instrumentedBinary)) {
        cerr << "Failed to write output file: " << instrumentedBinary << endl;
        return EXIT_FAILURE;
    }

    if(verbose){
        cout << "All done! Happy fuzzing!" << endl;
    }

    return EXIT_SUCCESS;


}