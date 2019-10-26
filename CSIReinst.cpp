/*
Re-instrument a previously instrumented binary;
It only instruments the functions that contains new edges.
The oracle binary is a previously instrumented binary which will
be re-instrumented.

*/



#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cstddef>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include "config.h"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

#include <map>
#include <sstream>
#include <climits>
#include <set>
#include <iterator>
#include <algorithm>
using namespace std;

#include "instConfig.h"
// DyninstAPI includes
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"


using namespace Dyninst;

//cmd line options
char *refBinary = NULL;
char *instrumentedBinary = NULL;
char *outputBinary = NULL;
bool verbose = false;
set<string> instrumentLibraries;
set<string> runtimeLibraries;
char* branch_dir = NULL;  //Output dir of examined branches
char* tracer_dir = NULL; //some addresses will be read from tracer
Category bin_cate = BIN_NONE; // category of the binary: crash/tracer/oracle
bool isOracle = false; //rosen



//addresses
multimap <unsigned long, unsigned long> indcall_addrs;
multimap <unsigned long, unsigned long> indjump_addrs; //de-duplicate indirect pairs
set <unsigned long> condnot_addrs;
set <unsigned long> condtaken_addrs;
// new blocks in tracer results; for finding functions with new blocks
set <unsigned long> new_condnot_addrs;
set <unsigned long> new_condtaken_addrs;

// addrs of marks (for differentiating paths)
multimap <unsigned long, unsigned long> mark_indcall_addrs;
multimap <unsigned long, unsigned long> mark_indjump_addrs;
set <unsigned long> mark_condnot_addrs;
set <unsigned long> mark_condtaken_addrs;


// callback functions
BPatch_function *initAflForkServer;
BPatch_function *getIndAddrs;
BPatch_function *BBCallback;
BPatch_function *ConditionJump;
BPatch_function *ConditionMark;
BPatch_function *IndirectBranch;
BPatch_function *clearMaps;




const char *instLibrary = "./libCSIReinst.so";

static const char *OPT_STR = "i:R:o:l:vB:E:r:CTOM";
static const char *USAGE = " -i <binary> -R <binary> -o <binary> -l <library> -B <out-dir> -E <tracer-dir> -O\n \
    Analyse options:\n \
            -i: The previous instrumented binary \n \
            -R: The reference binary for re-rewriting (the original binary)\n \
            -o: Output binary\n \
            -l: Linked library to instrument (repeat for more than one)\n \
            -r: Runtime library to instrument (path to, repeat for more than one)\n \
            -B: Output dir of examined branches (addresses)\n \
            -v: Verbose output\n \
            -E: Extended addresses from tracer\n \
    Binary type options:\n \
            -C: for the crash binary\n \
            -O: for the oracle binary\n";

bool parseOptions(int argc, char **argv)
{

    int c;
    while ((c = getopt (argc, argv, OPT_STR)) != -1) {
        switch ((char) c) {
        case 'i':
            instrumentedBinary = optarg;
            break;
        case 'R':
            refBinary = optarg;
            break;
        case 'o':
            outputBinary = optarg;
            break;
        case 'l':
            instrumentLibraries.insert(optarg);
            break;
        case 'r':
            runtimeLibraries.insert(optarg);
            break;
        case 'B':
            branch_dir = optarg;
            break;
        case 'E':
            tracer_dir = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'C':
            bin_cate = BIN_CRASH;
            break;
        case 'O':
            bin_cate = BIN_ORACLE;
            isOracle = true;
            break;
        default:
            cerr << "Usage: " << argv[0] << USAGE;
            return false;
        }
    }

    if(refBinary == NULL) {
        cerr << "Reference (Original) binary is required!"<< endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    
    if(instrumentedBinary == NULL) {
        cerr << "Previous instrumented binary is required!"<< endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(outputBinary == NULL) {
        cerr << "Output binary path is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(branch_dir == NULL){
        cerr << "Output directory for addresses is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(bin_cate == BIN_NONE){
        cerr << "The category oracle/crash (-O/-C) binary is required!" << endl;
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



/*insert callback to initialization function in the instrumentation library
main entry
*/  
bool insertCallToMainEE(BPatch_binaryEdit * appBin, BPatch_function * instIncFunc, BPatch_function *funcMain)
{
    /* Find the instrumentation points */
    vector < BPatch_point * >*funcLoc = funcMain->findPoint (BPatch_entry);

    if (NULL == funcLoc) {
        cerr << "Failed to find entry for function. " <<  endl;
        return false;
    }

    BPatch_Vector < BPatch_snippet * >instArgs; 
    BPatch_funcCallExpr instIncExpr (*instIncFunc, instArgs);

    /* Insert the snippet at function entry */
    BPatchSnippetHandle *handle =
        appBin->insertSnippet (instIncExpr, *funcLoc, BPatch_callBefore,
                               BPatch_lastSnippet);
    if (!handle) {
        cerr << "Failed to insert at main entry/exit callback." << endl;
        return false;
    }
    return true;
}

//main exit
bool insertCallToMainExit(BPatch_binaryEdit * appBin, BPatch_function * instIncFunc,
                         BPatch_function *funcInit){

    /* Find the instrumentation points */
    vector < BPatch_point * >*funcEntry = funcInit->findPoint (BPatch_exit);

    if (NULL == funcEntry) {
        cerr << "Failed to find exit for function main. " <<  endl;
        return false;
    }

    BPatch_Vector < BPatch_snippet * >instArgs; 
    BPatch_funcCallExpr instIncExpr (*instIncFunc, instArgs);

    /* Insert the snippet at function entry */
    BPatchSnippetHandle *handle =
        appBin->insertSnippet (instIncExpr, *funcEntry, BPatch_callAfter,
                               BPatch_lastSnippet);
    if (!handle) {
        cerr << "Failed to insert main callback." << endl;
        return false;
    }
    return true;
}



/* get address pairs, multimap/set 
main entry; after fork
*/
bool insertAddrsToInit(BPatch_binaryEdit * appBin, BPatch_function * instIncFunc, 
                        BPatch_function *funcInit, fs::path out_dir){

    /* Find the instrumentation points */
    vector < BPatch_point * >*funcEntry = funcInit->findPoint (BPatch_entry);

    if (NULL == funcEntry) {
        cerr << "Failed to find entry for function. " <<  endl;
        return false;
    }

    //cout << "Inserting init callback." << endl;
    BPatch_Vector < BPatch_snippet * >instArgs; 
    BPatch_constExpr outDir(out_dir.c_str());
    instArgs.push_back(&outDir);
    BPatch_funcCallExpr instIncExpr (*instIncFunc, instArgs);

    /* Insert the snippet at function entry */
    BPatchSnippetHandle *handle =
        appBin->insertSnippet (instIncExpr, *funcEntry, BPatch_callBefore,
                               BPatch_firstSnippet);
    if (!handle) {
        cerr << "Failed to insert init callback." << endl;
        return false;
    }
    return true;
}

// insert a callback for conditional marks
bool instrumentCondMarks(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
        BPatch_point * instrumentPoint, Dyninst::Address src_addr, Dyninst::Address des_addr){
    vector<BPatch_snippet *> cond_args;
    unsigned long tmp;
    tmp = (unsigned long)src_addr;
    BPatch_constExpr srcOffset(tmp);
    cond_args.push_back(&srcOffset);
    tmp = (unsigned long)des_addr;
    BPatch_constExpr desOffset(tmp);
    cond_args.push_back(&desOffset);


    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;
}

// insert a callback for conditional jumps
bool instrumentCondJump(BPatch_binaryEdit * appBin, BPatch_function * instFunc, BPatch_point * instrumentPoint, 
        Dyninst::Address src_addr, Dyninst::Address des_addr,fs::path out_path, fs::path mark_path){
    vector<BPatch_snippet *> cond_args;
    BPatch_constExpr srcOffset(src_addr);
    cond_args.push_back(&srcOffset);
    BPatch_constExpr desOffset(des_addr);
    cond_args.push_back(&desOffset);    
    BPatch_constExpr outPath(out_path.c_str());
    cond_args.push_back(&outPath);
    BPatch_constExpr markPath(mark_path.c_str());
    cond_args.push_back(&markPath);
    BPatch_constExpr CateBin(bin_cate);
    cond_args.push_back(&CateBin);

    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;
}


//insert a callback for indirect jumps
bool instrumentIndirectJump(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, Dyninst::Address src_addr, 
                fs::path out_path, fs::path mark_path, branType indi){
                    
    vector<BPatch_snippet *> ind_args;

    BPatch_constExpr srcOffset((unsigned long)src_addr);
    ind_args.push_back(&srcOffset);
    ind_args.push_back(new BPatch_dynamicTargetExpr());//target offset
    BPatch_constExpr outPath(out_path.c_str());
    ind_args.push_back(&outPath);
    BPatch_constExpr markPath(mark_path.c_str());
    ind_args.push_back(&markPath);
    BPatch_constExpr BranchT(indi);
    ind_args.push_back(&BranchT);
    BPatch_constExpr CateBin(bin_cate);
    ind_args.push_back(&CateBin);


    BPatch_funcCallExpr instIndirect(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instIndirect, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;
}



bool dedupMap(multimap <unsigned long, unsigned long>& ind_addrs, fs::path ind_path){
    /* remove duplicated elements in indirect jump records*/
    set<unsigned long> m_fir, m_sec; //use set to de-duplicate
    
    if (!ind_addrs.empty()){
        FILE *fm = fopen(ind_path.c_str(),"w");
        if (!fm){
            printf("cannot open file: %s.\n", ind_path.c_str());
            return false; //cannot remove file
        }
        fclose(fm);

        ofstream indAddr_io;
        //get source address
        for (auto addr_it = ind_addrs.begin(); addr_it != ind_addrs.end(); ++addr_it){
            m_fir.insert(addr_it->first);
        }
        //get target address without duplication
        for(auto fir_it = m_fir.begin(); fir_it!=m_fir.end(); ++fir_it){
            auto addr_eq = ind_addrs.equal_range(*fir_it);
            for(auto sec_it = addr_eq.first; sec_it != addr_eq.second; ++sec_it){
                m_sec.insert((*sec_it).second); //target addresses without duplication
            }

            indAddr_io.open (ind_path.c_str(), ios::out | ios::app | ios::binary); //write file
            if(indAddr_io.is_open()){
                for(auto tar_it= m_sec.begin(); tar_it!= m_sec.end(); ++tar_it){
                    indAddr_io << *fir_it << " " << *tar_it << endl;
                }
                indAddr_io.close();
                m_sec.clear();  
            }
            else{
                m_fir.clear();
                m_sec.clear();
                printf("cannot open file.\n");
                return false;
            } 
        }
        m_fir.clear();
    }

    return true;
}



/*
TrOr: when reading tracer addrs, mark addrs should not read
*/
bool readAdresses(fs::path outputDir, bool TrOr){
    unsigned long src, des;
    //file path
    fs::path condTaken_path = outputDir / COND_TAKEN;
    fs::path condNotTaken_path = outputDir / COND_NOT_TAKEN;
    fs::path indCall_path = outputDir / INDIRECT_CALL;
    fs::path indJump_path = outputDir / INDIRECT_JUMP;

    //condtaken_addrs
    ifstream condtaken_io (condTaken_path.c_str());
    if(condtaken_io.is_open()){
        while(condtaken_io >> src){
            condtaken_addrs.insert(src);
        }
        condtaken_io.close();
    }
    //condnot_addrs
    ifstream condnot_io (condNotTaken_path.c_str());
    if(condnot_io.is_open()){
        while(condnot_io >> src){
            condnot_addrs.insert(src);
        }
        condnot_io.close();
    }

    //indcall_addrs
    ifstream indcall_io (indCall_path.c_str());
    if (indcall_io.is_open()){
        while(indcall_io >> src >> des){
            indcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indcall_io.close();
    }

    //indjump_addrs
    ifstream indjump_io (indJump_path.c_str());
    if (indjump_io.is_open()){
        while(indjump_io >> src >> des){
            indjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indjump_io.close();
    }

    if (isOracle && TrOr){ //when reading tracer-addrs, mark-addrs should not be read
        fs::path mark_condTaken_path = outputDir / MARK_COND_TAKEN;
        fs::path mark_condNotTaken_path = outputDir / MARK_COND_NOT_TAKEN;
        fs::path mark_indCall_path = outputDir / MARK_INDIRECT_CALL;
        fs::path mark_indJump_path = outputDir / MARK_INDIRECT_JUMP;
        //condtaken_addrs
        ifstream mark_condtaken_io (mark_condTaken_path.c_str());
        if(mark_condtaken_io.is_open()){
            while(mark_condtaken_io >> src){
                //a bug: oracle writes an addr but tracer doesn't have the same addr 
                condtaken_addrs.insert(src);

                mark_condtaken_addrs.insert(src);
            }
            mark_condtaken_io.close();
        }
        //condnot_addrs
        ifstream mark_condnot_io (mark_condNotTaken_path.c_str());
        if(mark_condnot_io.is_open()){
            while(mark_condnot_io >> src){
                //a bug: oracle marks an addr but tracer doesn't write the same addr
                condnot_addrs.insert(src);
                
                mark_condnot_addrs.insert(src);
            }
            mark_condnot_io.close();
        }
        
        //indcall_addrs
        ifstream mark_indcall_io (mark_indCall_path.c_str());
        if (mark_indcall_io.is_open()){
            while(mark_indcall_io >> src >> des){
                //a bug: oracle marks an addr but tracer doesn't write the same addr
                indcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));

                mark_indcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
            }
            mark_indcall_io.close();
        }

        //indjump_addrs
        ifstream mark_indjump_io (mark_indJump_path.c_str());
        if (mark_indjump_io.is_open()){
            while(mark_indjump_io >> src >> des){
                //a bug: oracle marks an addr but tracer doesn't write the same addr
                indjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));

                mark_indjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
            }
            mark_indjump_io.close();
        }
    }

    return true;

}


/* 1. Read addresses from tracer results, and 
   2. get the new block addresses, and
   3. insert new blocks into whole recorded variables
    Indirect branches are compared dynamically, which can be instrumented by once; 
    so conditional braches are the only factor of re-instrumentation; 
    Therefore, the indirect edges are recorded into the variables indjump_addrs and indcall_addrs directly.
    However, conditional edges are recorded into different variables
*/
bool getNewBlockAddrs(fs::path outputDir){
    unsigned long src, des;
    set <unsigned long> common_addrs;
    //file path
    fs::path new_condTaken_path = outputDir / COND_TAKEN;
    fs::path new_condNotTaken_path = outputDir / COND_NOT_TAKEN;
    fs::path indCall_path = outputDir / INDIRECT_CALL;
    fs::path indJump_path = outputDir / INDIRECT_JUMP;

    //new condtaken_addrs
    //read address from tracer result
    ifstream new_condtaken_io (new_condTaken_path.c_str());
    if(new_condtaken_io.is_open()){
        while(new_condtaken_io >> src){
            new_condtaken_addrs.insert(src);
        }
        new_condtaken_io.close();
    }
    // remove the previously existing blocks in new_condtaken_addrs
    //get the intersection and store it in common_addrs
    std::set_intersection(condtaken_addrs.begin(), condtaken_addrs.end(),
                        new_condtaken_addrs.begin(), new_condtaken_addrs.end(),
                        std::inserter(common_addrs, common_addrs.begin()));
    // remove elements existing in both common_addrs and new_condtaken_addrs
    for (auto cait = common_addrs.begin(); cait != common_addrs.end(); ++cait){
        new_condtaken_addrs.erase(*cait);
    }
    // insert new blocks into the variable recording all condtaken addresses: condtaken_addrs
    for (auto nnit = new_condtaken_addrs.begin(); nnit != new_condtaken_addrs.end(); ++nnit){
        condtaken_addrs.insert(*nnit);
    }
    // clear common_addrs
    common_addrs.clear();

    //new condnot_addrs
    //read address from tracer result
    ifstream new_condnot_io (new_condNotTaken_path.c_str());
    if(new_condnot_io.is_open()){
        while(new_condnot_io >> src){
            new_condnot_addrs.insert(src);
        }
        new_condnot_io.close();
    }
    // remove the previously existing blocks in new_condtaken_addrs
    //get the intersection and store it in common_addrs
    std::set_intersection(condnot_addrs.begin(), condnot_addrs.end(),
                        new_condnot_addrs.begin(), new_condnot_addrs.end(),
                        std::inserter(common_addrs, common_addrs.begin()));
    // remove elements existing in both common_addrs and new_condnot_addrs
    for (auto cait = common_addrs.begin(); cait != common_addrs.end(); ++cait){
        new_condnot_addrs.erase(*cait);
    }
    // insert new blocks into the variable recording all condnot addresses: condnot_addrs
    for (auto cnit = new_condnot_addrs.begin(); cnit != new_condnot_addrs.end(); ++cnit){
        condnot_addrs.insert(*cnit);
    }
    // clear common_addrs
    common_addrs.clear();


    //indcall_addrs
    ifstream indcall_io (indCall_path.c_str());
    if (indcall_io.is_open()){
        while(indcall_io >> src >> des){
            indcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indcall_io.close();
    }

    //indjump_addrs
    ifstream indjump_io (indJump_path.c_str());
    if (indjump_io.is_open()){
        while(indjump_io >> src >> des){
            indjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indjump_io.close();
    }
    
    return true;
}

bool rewriteCondAddr(set<unsigned long> &cond_addrs, fs::path cond_path){
    FILE *fm = fopen(cond_path.c_str(),"w");
    if (!fm){
        printf("cannot open file: %s.\n", cond_path.c_str());
        return false; //cannot delete file contents
    }
    fclose(fm); //delete contents

    if(!cond_addrs.empty()){
        ofstream waddrs;
        waddrs.open (cond_path.c_str(), ios::out | ios::app | ios::binary); //write file
        if(waddrs.is_open()){
            for(auto coit = cond_addrs.begin(); coit != cond_addrs.end(); ++coit){
                waddrs << *coit << endl;
            }
            waddrs.close();
            return true;
        }
        else return false;
    }
    return true;
}

void dealAddressFiles(fs::path outputDir){
    
    //main binary
    readAdresses(outputDir, true);

    if(isOracle){

        fs::path markcondTaken_path = outputDir / MARK_COND_TAKEN;
        fs::path markcondNotTaken_path = outputDir / MARK_COND_NOT_TAKEN;
        fs::path markindCall_path = outputDir / MARK_INDIRECT_CALL;
        fs::path markindJump_path = outputDir / MARK_INDIRECT_JUMP;
        if(!dedupMap(mark_indcall_addrs, markindCall_path)){
            printf("error in de-duplicate call addresses.\n");
            exit(EXIT_FAILURE);
        }

        if(!dedupMap(mark_indjump_addrs, markindJump_path)){
            printf("error in de-duplicate jump addresses.\n");
            exit(EXIT_FAILURE);
        }

        if(!rewriteCondAddr(mark_condtaken_addrs, markcondTaken_path)){
            printf("error in re-writing condition taken addresses.\n");
            exit(EXIT_FAILURE);
        }
        if (!rewriteCondAddr(mark_condnot_addrs, markcondNotTaken_path)){
            printf("error in re-writing condition not taken addresses.\n");
            exit(EXIT_FAILURE);
        } 
    } 

    /* from tracer */
    if(tracer_dir != NULL){
        fs::path tracerDir(tracer_dir);
        //file path
        fs::path condTaken_path = outputDir / COND_TAKEN;
        fs::path condNotTaken_path = outputDir / COND_NOT_TAKEN;
        fs::path indCall_path = outputDir / INDIRECT_CALL;
        fs::path indJump_path = outputDir / INDIRECT_JUMP;
        
        //readAdresses(tracerDir, false);

        //read records from tracer; get the new blocks;
        getNewBlockAddrs(tracerDir);

        // after getNewBlockAddrs(), indcall_addrs et al. are inserted new blocks
        if(!dedupMap(indcall_addrs, indCall_path)){
            printf("error in de-duplicate call addresses.\n");
            exit(EXIT_FAILURE);
        }

        if(!dedupMap(indjump_addrs, indJump_path)){
            printf("error in de-duplicate jump addresses.\n");
            exit(EXIT_FAILURE);
        }

        if(!rewriteCondAddr(condtaken_addrs, condTaken_path)){
            printf("error in re-writing condition taken addresses.\n");
            exit(EXIT_FAILURE);
        }
        if (!rewriteCondAddr(condnot_addrs, condNotTaken_path)){
            printf("error in re-writing condition not taken addresses.\n");
            exit(EXIT_FAILURE);
        }         
    }

}



/*whether the paddr has been Examined
* true: has been Examined 
* false: has not been Examined
*/
bool isExamined(Dyninst::Address paddr, branType type){
    unsigned long addr_find = (unsigned long)paddr;
    set <unsigned long> temp_cond;
    switch(type){
        case TYPE_CTAKEN:
            temp_cond = condtaken_addrs;
            break;
        case TYPE_NCTAKEN:
            temp_cond = condnot_addrs;
            break;
        default:
            cout << "wrong insert type!!" << endl;
            return false;
    }
    if (!temp_cond.empty()){
        if (temp_cond.count(addr_find)) return true;
        else return false;
            }
    else //no recorded addresses
    {
        return false;
    }

}

/*whether the src_addr has been recorded as a mark
* true: is a mark
* false: not a mark
*/
bool isMarks(Dyninst::Address src_addr, branType type){
    unsigned long addr_find = (unsigned long)src_addr;
    set <unsigned long> temp_cond;
    switch(type){
        case TYPE_CTAKEN:
            temp_cond = mark_condtaken_addrs;
            break;
        case TYPE_NCTAKEN:
            temp_cond = mark_condnot_addrs;
            break;
        default:
            cout << "wrong type of marks!!" << endl;
            return false;
    }
    if (!temp_cond.empty()){
        if (temp_cond.count(addr_find)) return true;
        else return false;
    }
    else //no recorded addresses
    {
        return false;
    }

}

//clear maps
void clearAddrMaps(void){
    condnot_addrs.clear();
    condtaken_addrs.clear();
    indcall_addrs.clear();
    indjump_addrs.clear();

    new_condnot_addrs.clear();
    new_condtaken_addrs.clear();

    mark_condnot_addrs.clear();
    mark_condtaken_addrs.clear();
    mark_indcall_addrs.clear();
    mark_indjump_addrs.clear();
}

/* for each brach, insert ID; used for bitmap*/
bool insertBranchID(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, unsigned short id){
    vector<BPatch_snippet *> ind_args;
    BPatch_constExpr cbID(id);
    ind_args.push_back(&cbID);
    
    BPatch_funcCallExpr instFuncID(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instFuncID, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention branch id: " <<
                 id << endl;
            return false;
        }
    return true;
}

/* check whether the function contains any new blocks 
Return true if all the blocks are not new blocks; 
otherwise, if any of them are new, return false;
*/
bool noNewBlocks(BPatch_Set < BPatch_basicBlock * >& AllBlocks){
    set < BPatch_basicBlock *>::iterator bb_iter;
    unsigned long addr_find;
    // if new_*_addrs are empty, all the blocks are not new
    if (new_condnot_addrs.empty()) {
        if (new_condtaken_addrs.empty()) return true;
    }
    
    for (bb_iter = AllBlocks.begin (); bb_iter != AllBlocks.end (); bb_iter++){
        BPatch_basicBlock * block = *bb_iter;
        vector<pair<Dyninst::InstructionAPI::Instruction, Dyninst::Address> > insns;
        block->getInstructions(insns);

        Dyninst::Address addr = insns.back().second;  //addr: equal to offset when it's binary rewrite
        addr_find = (unsigned long)addr;
        
        if (new_condnot_addrs.count(addr_find)){// exist a new block
            return false;
        }
        if (new_condtaken_addrs.count(addr_find)){// exist a new block
            return false;
        }

    }

    return true;
}

bool insertBBCallback(BPatch_binaryEdit * appBin, BPatch_image *appImage, vector < BPatch_function * >::iterator funcIter,
                            char *funcName, fs::path out_dir){
    BPatch_function *curFunc = *funcIter;

    fs::path condTakenPath = out_dir / COND_TAKEN;
    fs::path condNotPath = out_dir / COND_NOT_TAKEN;
    fs::path IndJumpPath = out_dir / INDIRECT_JUMP;
    fs::path IndCallPath = out_dir / INDIRECT_CALL;
    //for path marks
    fs::path markTakenPath = out_dir / MARK_COND_TAKEN;
    fs::path markNotPath = out_dir / MARK_COND_NOT_TAKEN;
    fs::path markJumpPath = out_dir / MARK_INDIRECT_JUMP;
    fs::path markCallPath = out_dir / MARK_INDIRECT_CALL;

    /* Other blocks to ignore. */
    /* 
         
        string(funcName) == string("cJSON_Delete") ||
        string(funcName) == string("free") ||
        string(funcName) == string("fnmatch") ||
        string(funcName) == string("readlinkat") ||
        string(funcName) == string("malloc") ||
        string(funcName) == string("calloc") ||
        string(funcName) == string("realloc") ||
        string(funcName) == string("argp_failure") ||
        string(funcName) == string("argp_help") ||
        string(funcName) == string("argp_state_help") ||
        string(funcName) == string("argp_error") ||
        string(funcName) == string("argp_parse") || 

    */
    
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
        string(funcName) == string("_start") ||  // here's a bug on hlt
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
        return true; //continue to insert
    }
    
    BPatch_flowGraph *appCFG = curFunc->getCFG ();
    if (!appCFG) {
        cerr << "Failed to find CFG for function " << funcName << endl;
        clearAddrMaps();
        return false;
    }

    BPatch_Set < BPatch_basicBlock * > allBlocks;
    if (!appCFG->getAllBasicBlocks (allBlocks)) {
        cerr << "Failed to find basic blocks for function " << funcName << endl;
        clearAddrMaps();
        return false;
    } else if (allBlocks.size () == 0) {
        cerr << "No basic blocks for function " << funcName << endl;
        clearAddrMaps();
        return false;
    }

    //check whether the function needs to be instrumented
    if (noNewBlocks(allBlocks)) return true;

    /*OK, let's instrument the function */

    // special instrumentation for function main
    if (string(funcName) == string("main")) {
            //insert function initAflForkServer at the entry of main
        BPatch_function *funcToPatch = NULL;
        BPatch_Vector<BPatch_function*> funcs;
        
        appImage->findFunction("main",funcs);
        if(!funcs.size()) {
            cerr << "Couldn't locate main, check your binary. "<< endl;
            return EXIT_FAILURE;
        }
        // there should really be only one
        funcToPatch = funcs[0];
    
        if(!funcToPatch) {
            cerr << "Couldn't locate function at given entry point. "<< endl;
            return EXIT_FAILURE;
        }
        // insert forkserver
        if(!insertCallToMainEE (appBin,  initAflForkServer, funcToPatch)){
            cerr << "Could not insert init callback at main." << endl;
            return EXIT_FAILURE;
        }
        // insert function to get initial addresses
        if(!insertAddrsToInit (appBin,  getIndAddrs, funcToPatch, out_dir)){
            cerr << "Could not insert init callback at main." << endl;
            return EXIT_FAILURE;
        }
        // at the end of main function, insert function to clear multimaps
        if(!insertCallToMainExit (appBin,  clearMaps, funcToPatch)){
            cerr << "Could not insert main exit callback at main." << endl;
            return EXIT_FAILURE;
        }

    }

    //unsigned short block_id;
    //BPatch_Set < BPatch_basicBlock * >::iterator bb_iter;
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

        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            /*get the starting addresses of source and target blocks of this edge*/
            // BPatch_basicBlock * src_block = (*edge_iter)->getSource();
            BPatch_basicBlock * des_block = (*edge_iter)->getTarget();
            // unsigned long src_block_addr = src_block->getStartAddress();
            unsigned long des_block_addr = des_block->getStartAddress();
            
            //insert for new coverage
            // ||(*edge_iter)->getType() == NonJump
            // (*edge_iter)->getType() == UncondJump
            /* the addresses in condition-taken path includes 
             *conditional jump(taken), unconditional jump, no jump */
            if ((*edge_iter)->getType() == CondJumpTaken){
                if (!isExamined(addr, TYPE_CTAKEN)){
                    instrumentCondJump(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, des_block_addr, condTakenPath, markTakenPath);
                }

                if (isOracle){
                        if (isMarks(addr, TYPE_CTAKEN)){
                        instrumentCondMarks(appBin, ConditionMark, (*edge_iter)->getPoint(), addr, des_block_addr);
                    }
                }
                

            }
            else if ((*edge_iter)->getType() == CondJumpNottaken){
               
                if (!isExamined(addr, TYPE_NCTAKEN)){
                    instrumentCondJump(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, des_block_addr, condNotPath, markNotPath);
                }

                if (isOracle){
                    if (isMarks(addr, TYPE_NCTAKEN)){
                        instrumentCondMarks(appBin, ConditionMark, (*edge_iter)->getPoint(), addr, des_block_addr);
                    }
                }
                
                
            }
            // else if ((*edge_iter)->getType() == UncondJump){
             
            //     if (!isExamined(addr, TYPE_CTAKEN)){
            //         instrumentCondJump(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, des_block_addr, condTakenPath,markTakenPath);
            //     }
            // }
            // else if ((*edge_iter)->getType() == NonJump){
               
            //     if (!isExamined(addr, TYPE_CTAKEN)){
            //         instrumentCondJump(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, des_block_addr, condTakenPath,markTakenPath);
            //     }
            // }                    
            
        }

        //indirect jumps
        for(Dyninst::InstructionAPI::Instruction::cftConstIter iter = insn.cft_begin(); iter != insn.cft_end(); ++iter) {
            if(iter->isIndirect) {
                
                if(category == Dyninst::InstructionAPI::c_CallInsn) {
                    vector<BPatch_point *> callPoints;
                    appImage->findPoints(addr, callPoints);
                    
                    vector<BPatch_point *>::iterator callPt_iter;
                    for(callPt_iter = callPoints.begin(); callPt_iter != callPoints.end(); ++callPt_iter) {
                        
                        instrumentIndirectJump(appBin, IndirectBranch, *callPt_iter, addr, IndCallPath, markCallPath, TYPE_CALL);                         
                    }
                }
                
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {
                    vector<BPatch_point *> jmpPoints;
                    appImage->findPoints(addr, jmpPoints);
                    
                    vector<BPatch_point *>::iterator jmpPt_iter;
                    for(jmpPt_iter = jmpPoints.begin(); jmpPt_iter != jmpPoints.end(); ++jmpPt_iter) {
                        
                        instrumentIndirectJump(appBin, IndirectBranch, *jmpPt_iter, addr, IndJumpPath, markJumpPath, TYPE_JUMP);
                    }
                }
                // //"return" is actually an indirect call
                // else if(category == Dyninst::InstructionAPI::c_ReturnInsn) {
                //     vector<BPatch_point *> retPoints;
                //     appImage->findPoints(addr, retPoints);

                //     vector<BPatch_point *>::iterator retPt_iter;
                //     for(retPt_iter = retPoints.begin(); retPt_iter != retPoints.end(); ++retPt_iter) {
                //         instrumentIndirectJump(appBin, IndirectBranch, *retPt_iter, addr, IndCallPath, markCallPath, TYPE_CALL);
                //     }
                // }
            }
        }
    }
    return true;
}




int main (int argc, char **argv)
{
    if(!parseOptions(argc,argv)) {
        return EXIT_FAILURE;
    }

    fs::path out_dir (reinterpret_cast<const char*>(branch_dir)); // files for jump/call addresses


    if (NULL==opendir(out_dir.c_str())){
        mkdir(out_dir.c_str(),0777);
    }

    /* start instrumentation*/
    BPatch bpatch;
    // skip all libraries unless -l is set
    BPatch_binaryEdit *appBin = bpatch.openBinary (instrumentedBinary, false);
    if (appBin == NULL) {
        cerr << "Failed to open binary" << endl;
        return EXIT_FAILURE;
    }

    if(refBinary != NULL){
        appBin->openReferenceBinary(refBinary);
    }

    if(!instrumentLibraries.empty()){
        for(auto lbit = instrumentLibraries.begin(); lbit != instrumentLibraries.end(); lbit++){
            if (!appBin->loadLibrary ((*lbit).c_str())) {
                cerr << "Failed to open instrumentation library " << *lbit << endl;
                cerr << "It needs to be located in the current working directory." << endl;
                return EXIT_FAILURE;
            }
        }
    }

    BPatch_image *appImage = appBin->getImage();

    
    vector < BPatch_function * > allFunctions;
    appImage->getProcedures(allFunctions);

    if (!appBin->loadLibrary (instLibrary)) {
        cerr << "Failed to open instrumentation library " << instLibrary << endl;
        cerr << "It needs to be located in the current working directory." << endl;
        return EXIT_FAILURE;
    }

    
    initAflForkServer = findFuncByName (appImage, (char *) "initAflForkServer");
    IndirectBranch = findFuncByName (appImage, (char *) "IndirectBranch");
    
    
    //indirect addresses pairs
    getIndAddrs = findFuncByName (appImage, (char *) "getIndirectAddrs");
    clearMaps = findFuncByName (appImage, (char *) "clearMultimaps");
    
    //conditional jumps
    ConditionJump = findFuncByName (appImage, (char *) "ConditionJump");
    BBCallback =  findFuncByName (appImage, (char *) "BBCallback");
    ConditionMark = findFuncByName (appImage, (char *) "ConditionMark");
    


    if (!initAflForkServer || !ConditionJump || !IndirectBranch || !ConditionMark
        || !getIndAddrs || !clearMaps || !BBCallback) {
        cerr << "CSIReinst instrumentation library lacks callbacks!" << endl;
        return EXIT_FAILURE;
    }

    
    /*reading files containing addresses, and skip those addresses while instrumentation*/
    
    dealAddressFiles(out_dir);

    vector < BPatch_function * >::iterator funcIter;
    // iterate over all functions
    for (funcIter = allFunctions.begin (); funcIter != allFunctions.end (); ++funcIter) {
        BPatch_function *curFunc = *funcIter;
        char funcName[1024];
        curFunc->getName (funcName, 1024);
        if(!insertBBCallback(appBin, appImage, funcIter, funcName, out_dir)) return EXIT_FAILURE;        
    }

    // //insert function initAflForkServer at the entry of main
    // BPatch_function *funcToPatch = NULL;
    // BPatch_Vector<BPatch_function*> funcs;
    
    // appImage->findFunction("main",funcs);
    // if(!funcs.size()) {
    //     cerr << "Couldn't locate main, check your binary. "<< endl;
    //     return EXIT_FAILURE;
    // }
    // // there should really be only one
    // funcToPatch = funcs[0];
  
    // if(!funcToPatch) {
    //     cerr << "Couldn't locate function at given entry point. "<< endl;
    //     return EXIT_FAILURE;
    // }

    // if(!insertCallToMainEE (appBin,  initAflForkServer, funcToPatch)){
    //     cerr << "Could not insert init callback at main." << endl;
    //     return EXIT_FAILURE;
    // }
    // if(!insertAddrsToInit (appBin,  getIndAddrs, funcToPatch, out_dir)){
    //     cerr << "Could not insert init callback at main." << endl;
    //     return EXIT_FAILURE;
    // }
    // // at the end of main function, insert function to clear multimaps
    // if(!insertCallToMainExit (appBin,  clearMaps, funcToPatch)){
    //     cerr << "Could not insert main exit callback at main." << endl;
    //     return EXIT_FAILURE;
    // }



    if(verbose){
        cout << "Saving the currently instrumented binary to " << outputBinary << "..." << endl;
    }
    // Output the instrumented binary
    if (!appBin->writeFile (outputBinary)) {
        cerr << "Failed to write output file: " << outputBinary << endl;
        return EXIT_FAILURE;
    }

    /* for runtime libraries that are manually pointed */
    if(!runtimeLibraries.empty()) {
        cout << "Instrumenting runtime libraries." << endl;
        set<string>::iterator rtLibIter ;
        for(rtLibIter = runtimeLibraries.begin(); rtLibIter != runtimeLibraries.end(); rtLibIter++) {
            BPatch_binaryEdit *libBin = bpatch.openBinary ((*rtLibIter).c_str(), false);
            if (libBin == NULL) {
                cerr << "Failed to open binary "<< *rtLibIter << endl;
                return EXIT_FAILURE;
            }
            
            BPatch_image *libImg = libBin->getImage ();
            vector < BPatch_function * > libFunctions;
            libImg->getProcedures(libFunctions);

            libBin->loadLibrary (instLibrary);
            vector < BPatch_function * >::iterator funcIter;
            // iterate over all functions
            for (funcIter = libFunctions.begin (); funcIter != libFunctions.end ();
                    ++funcIter) {
                BPatch_function *curFunc = *funcIter;
                char funcName[1024];
                curFunc->getName (funcName, 1024);
                if (!insertBBCallback(libBin, libImg, funcIter, funcName, out_dir)) return EXIT_FAILURE;
            }
         
            if (!libBin->writeFile ((*rtLibIter + ".ins").c_str())) {
                cerr << "Failed to write output file: " <<(*rtLibIter + ".ins").c_str() << endl;
                return EXIT_FAILURE;
            } else {
                if(verbose){
                    cout << "Saved the instrumented library to " << (*rtLibIter + ".ins").c_str() << "." << endl;
                }
            }
        }
    }

    clearAddrMaps();

    if(verbose){
        cout << "All done! Happy fuzzing!" << endl;
    }

    return EXIT_SUCCESS;

}
