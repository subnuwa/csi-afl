#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include "config.h"
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>

#include <stdio.h> 
#include <stdlib.h> 

#include <map>
#include "instConfig.h"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
using namespace std;


static u8* trace_bits;
static s32 shm_id;                    /* ID of the SHM region             */
static unsigned short prev_id;
//examined branches
multimap <unsigned long, unsigned long> lindcall_addrs;
multimap <unsigned long, unsigned long> lindjump_addrs;
// marked branches
multimap <unsigned long, unsigned long> mark_lindcall_addrs;
multimap <unsigned long, unsigned long> mark_lindjump_addrs;

/* This is for the dummy tracer - i.e., it exits when hitting <main>. */
void atMainExit() {
	exit(0);
}

void initAflForkServer()
{
    int temp_data;
    pid_t fork_pid;

    /* Set up the SHM bitmap. */
    char *shm_env_var = getenv(SHM_ENV_VAR);
    if(!shm_env_var) {
        printf("Error getting shm\n");
        return;
    }
    shm_id = atoi(shm_env_var);
    trace_bits = (u8*)shmat(shm_id, NULL, 0);
    if(trace_bits == (u8*)-1) {
        perror("shmat");
        return;
    }

    // enter fork() server thyme!
    //int n;
    if( write(FORKSRV_FD+1, &temp_data, 4) !=4 ) {
        perror("Error writting fork server\n");
        return;
    }
    /* All right, let's await orders... */
    while(1) {
        int stMsgLen = read(FORKSRV_FD, &temp_data, 4);
        if(stMsgLen != 4) {
            /* we use a status message length 2 to terminate the fork server. */
            if(stMsgLen == 2){
                exit(EXIT_SUCCESS);
            }
				
            printf("Error reading fork server %x\n",temp_data);
            return;
        }
        /* Parent - Fork off worker process that actually runs the benchmark. */
        fork_pid = fork();
        if(fork_pid < 0) {
            printf("Error on fork()\n");
            return;
        }
        /* Child worker - Close descriptors and return (runs the benchmark). */
        if(fork_pid == 0) {
            close(FORKSRV_FD);
            close(FORKSRV_FD+1);
            //printf("child process\n");
            return;
        } 
        
        /* Parent - Inform controller that we started a new run. */
		if (write(FORKSRV_FD + 1, &fork_pid, 4) != 4) {
    		perror("Fork server write(pid) failed");
			exit(EXIT_FAILURE);
  		}

        /* Parent - Sleep until child/worker finishes. */
		if (waitpid(fork_pid, &temp_data, 2) < 0) {//2: WUNTRACED
    		perror("Fork server waitpid() failed"); 
			exit(EXIT_FAILURE);
  		}

        /* Parent - Inform controller that run finished. 
            * write status (temp_data) of waitpid() to the pipe
        */
		if (write(FORKSRV_FD + 1, &temp_data, 4) != 4) {
    		perror("Fork server write(temp_data) failed");
			exit(EXIT_FAILURE);
  		}
  		/* Jump back to beginning of this loop and repeat. */


    }

}


/*get indirect call/jump address pairs.
this function should be called before forkserver,
then the multimap can be re-used 
*/
void getIndirectAddrs(char* base_dir){
    unsigned long src, des;
    fs::path outputDir (base_dir);
    fs::path indCall_file (INDIRECT_CALL);
    fs::path indJump_file (INDIRECT_JUMP);
    fs::path indCall_path = outputDir / indCall_file;
    fs::path indJump_path = outputDir / indJump_file;

    //indcall_addrs
    ifstream indcall_io (indCall_path.c_str());
    if (indcall_io.is_open()){
        while(indcall_io >> src >> des){
            lindcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indcall_io.close();
    }

    //indjump_addrs
    ifstream indjump_io (indJump_path.c_str());
    if (indjump_io.is_open()){
        while(indjump_io >> src >> des){
            lindjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        indjump_io.close();
    }

    /* for path marks */
    fs::path mark_indCall_file (MARK_INDIRECT_CALL);
    fs::path mark_indJump_file (MARK_INDIRECT_JUMP);
    fs::path mark_indCall_path = outputDir / mark_indCall_file;
    fs::path mark_indJump_path = outputDir / mark_indJump_file;

    //indcall_addrs
    ifstream mark_indcall_io (mark_indCall_path.c_str());
    if (mark_indcall_io.is_open()){
        while(mark_indcall_io >> src >> des){
            mark_lindcall_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        mark_indcall_io.close();
    }

    //indjump_addrs
    ifstream mark_indjump_io (mark_indJump_path.c_str());
    if (mark_indjump_io.is_open()){
        while(mark_indjump_io >> src >> des){
            mark_lindjump_addrs.insert(std::pair<unsigned long, unsigned long>(src,des));
        }
        mark_indjump_io.close();
    }

}

/* clear multimap at the end*/
void clearMultimaps(void){
    lindcall_addrs.clear();
    lindjump_addrs.clear();
    mark_lindcall_addrs.clear();
    mark_lindjump_addrs.clear();
}

//indirect branches (call/jump)
void IndirectBranch(unsigned long src_offset, unsigned long des_offset, const char* indirect_path, 
                 const char* mark_path, branType indi, Category bin_cate=BIN_NONE) {

    bool exit_flag, bin_write, isoracle=false;
    switch(bin_cate){
        case BIN_CRASH:
            exit_flag = true;
            bin_write = false;
            break;
        case BIN_TRACER:
            exit_flag = false;
            bin_write = true;
            break;
        case BIN_ORACLE:
            exit_flag = true;
            bin_write = false;
            isoracle = true;
            break;
        case BIN_TRIMMER:
            exit_flag = false;
            bin_write = false;
            break;
        default:
            printf("indirect has no para Category!\n");
            return;
    }

    
    int msize =0;
    bool new_flag= true;
    multimap <unsigned long, unsigned long> ind_tmp;
    if (indi==TYPE_CALL) ind_tmp = lindcall_addrs;
    else ind_tmp = lindjump_addrs;

        // for path marks, if the edge has been recorded, write to shared memory
    if (isoracle){
        bool mark_flag= false;
        multimap <unsigned long, unsigned long> mark_tmp;
        if (indi==TYPE_CALL) mark_tmp = mark_lindcall_addrs;
        else mark_tmp = mark_lindjump_addrs;
        msize = 0;
        if (!mark_tmp.empty()){
            msize = mark_tmp.count(src_offset);
            if (0 != msize){
                multimap <unsigned long, unsigned long>::iterator ite_addr;
                auto all_src = mark_tmp.equal_range(src_offset);
                for (ite_addr=all_src.first; ite_addr!=all_src.second; ++ite_addr){
                    if (des_offset == (*ite_addr).second){
                        mark_flag = true; // if the target addr is recoded, it's the mark addr
                        break;
                    } 
                }
            }

        }
        // write addrs to the shard memory
        if(mark_flag){
            if(trace_bits){
                unsigned char tmp;
                for(int i=0; i< MARK_SIZE;i++){
                    // trace_bits[MAP_SIZE] is the lowest byte
                    tmp = (unsigned char)((src_offset >> (i*8)) & 0xff);
                    trace_bits[MAP_SIZE+i] = tmp;
                    // trace_bits[MAP_SIZE+ MARK_SIZE] is the lowest byte
                    tmp = (unsigned char)((des_offset >> (i*8)) & 0xff);
                    trace_bits[MAP_SIZE + MARK_SIZE + i] = tmp;
                }     
            }
            
        }
    }

    // for indirect branches
    if (!ind_tmp.empty()){
        msize = ind_tmp.count(src_offset);
        if (0 != msize){
            multimap <unsigned long, unsigned long>::iterator ite_addr;
            auto all_src = ind_tmp.equal_range(src_offset);
            for (ite_addr=all_src.first; ite_addr!=all_src.second; ++ite_addr){
                if (des_offset == (*ite_addr).second){
                    new_flag = false;
                    break;
                } 
            }
        }

    }
    
    if(new_flag){
        if(bin_write){
            ofstream indaddrs;
            indaddrs.open (indirect_path, ios::out | ios::app | ios::binary); //write file
            if(indaddrs.is_open()){
                indaddrs << src_offset << " " << des_offset << endl; 
            }


        }

        //for path mark, write to record seed when a new edge is met
        if(isoracle){
            ofstream markaddrs;
            markaddrs.open (mark_path, ios::out | ios::app | ios::binary); //write file
            if(markaddrs.is_open()){
                markaddrs << src_offset << " " << des_offset << endl;
                markaddrs.close();  
            }
            /* write addrs to the shard memory, this will be recorded in queue
            * and be used like a path checksum */
            if(trace_bits){
                unsigned char tmp;
                for(int i=0; i< MARK_SIZE;i++){
                    // trace_bits[MAP_SIZE] is the lowest byte
                    tmp = (unsigned char)((src_offset >> (i*8)) & 0xff);
                    trace_bits[MAP_SIZE+i] = tmp;
                    // trace_bits[MAP_SIZE+ MARK_SIZE] is the lowest byte
                    tmp = (unsigned char)((des_offset >> (i*8)) & 0xff);
                    trace_bits[MAP_SIZE + MARK_SIZE + i] = tmp;
                }     
            }

        }

        if(exit_flag){ 
            exit(INDIRECT_COVERAGE); //tell parent we find new coverage
        } 
    }

}


// conditional jumps
void ConditionJump(unsigned long src_addr, unsigned long des_addr, 
                    const char* cond_path, const char* mark_path, Category bin_cate=BIN_NONE) {
    bool exit_flag, bin_write, isOracle=false;
    switch(bin_cate){
        case BIN_CRASH:
            exit_flag = true;
            bin_write = false;
            break;
        case BIN_TRACER:
            exit_flag = false;
            bin_write = true;
            break;
        case BIN_ORACLE:
            exit_flag = true;
            bin_write = false;
            isOracle = true;
            break;
        case BIN_TRIMMER:
            exit_flag = false;
            bin_write = false;
            break;
        default:
            printf("condition has no para Category!\n");
            return;
    }


    if (bin_write){
        ofstream condaddrs;
        condaddrs.open (cond_path, ios::out | ios::app | ios::binary); //write file
        if(condaddrs.is_open()){
            condaddrs << src_addr << endl;
        }
        
    }

    if(isOracle){
        ofstream markaddrs;
        markaddrs.open (mark_path, ios::out | ios::app | ios::binary); //write file
        if(markaddrs.is_open()){
            markaddrs << src_addr << endl; // record path marks
            markaddrs.close();
        }
        if(trace_bits){
            unsigned char tmp;
            for(int i=0; i < MARK_SIZE; i++){
                // trace_bits[MAP_SIZE] is the lowest byte
                tmp = (unsigned char)((src_addr >> (i*8)) & 0xff);
                trace_bits[MAP_SIZE+i] = tmp;
                // trace_bits[MAP_SIZE+ MARK_SIZE] is the lowest byte
                tmp = (unsigned char)((des_addr >> (i*8)) & 0xff);
                trace_bits[MAP_SIZE + MARK_SIZE + i] = tmp;
            }     
        }
    }

    if(exit_flag){ 
        exit(COND_COVERAGE);
    }
}

void ConditionMark(unsigned long src_offset, unsigned long des_offset){
    if(trace_bits){
        unsigned char tmp;
        for(int i=0; i < MARK_SIZE; i++){
            // trace_bits[MAP_SIZE] is the lowest byte
            tmp = (unsigned char)((src_offset >> (i*8)) & 0xff);
            trace_bits[MAP_SIZE+i] = tmp;
            // trace_bits[MAP_SIZE+ MARK_SIZE] is the lowest byte
            tmp = (unsigned char)((des_offset >> (i*8)) & 0xff);
            trace_bits[MAP_SIZE + MARK_SIZE + i] = tmp;
        }     
    }
}

// bitmap id for edges just like afl
void BBCallback(unsigned short id)
{
    if(trace_bits) {
        trace_bits[prev_id ^ id]++;
        prev_id = id >>1;
    }
}



