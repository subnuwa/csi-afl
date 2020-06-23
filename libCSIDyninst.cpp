#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>

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
#include <set>

#include "config.h"
#include "instConfig.h"
#include "instUnmap.h"
#include "types.h"


#include <experimental/filesystem>

using namespace std;
namespace fs = std::experimental::filesystem;


static u8* trace_bits;
static s32 shm_id;                    /* ID of the SHM region             */
//static unsigned short prev_id;
//examined indirect edges and their ids, [(src_addr, des_addr), id]
std::unordered_map<EDGE, u32, HashEdge> indirect_ids;

static u32 cur_max_id; // the current id of indirect edges


/* 
    max_predtm: the largest number of pre-determined edges
    indirect_file: this file is used when afl wants to re-run the target and use previous results;
                    it contains three number in a row: (src_addr des_addr id)
    marks_file: marks in the file; [mark_id]
*/
void initAflForkServer(u32 max_predtm, const char* indirect_file){
    /* start fork */
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

    /*recover indirect ids*/  
    u64 ind_src, ind_des;
    u32 addr_id;
    // the max id of indirect edges while fuzzing
    cur_max_id = max_predtm - 1; // max_predtm: the max id of pre-determined edges

   
    ifstream indirect_io (indirect_file); //read file
    if (indirect_io.is_open()){
        while(indirect_io >> ind_src >> ind_des >> addr_id){
            indirect_ids.insert(make_pair(EDGE(ind_src, ind_des), addr_id));
            if (addr_id > cur_max_id) cur_max_id = addr_id;
        }
        indirect_io.close();
    }
    
    

    /* All right, let's await orders... */
    while(1) {
        
        int stMsgLen = read(FORKSRV_FD, &temp_data, 4);
        if(stMsgLen != 4) {
            /* we use a status message length 2 to indicate a new reading from file. */
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

/* Oracle predetermined edges: only for marks
    exit if not examined, add path mark; record path mark for cksum  
    predtm_id: pre-determined id
    path mark can only be gotten from oracle
*/
void OraclePredtm(u32 predtm_id){
    if (trace_bits){
        if ((trace_bits[predtm_id + MAP_SIZE] & EDGE_COVERED) == 1){ // have not been examined;
            trace_bits[predtm_id + MAP_SIZE] &= 252; //set examined and marked, 1111 1100
            trace_bits[predtm_id] = 1; //leave marks
       
            trace_bits[MAP_SIZE + BYTES_FLAGS + FLAG_LOOP] = COND_COVERAGE;
            exit(COND_COVERAGE);
        }
        
        // examined
        if ((trace_bits[predtm_id + MAP_SIZE]& EDGE_MARK )== 0){ // marked
            trace_bits[predtm_id] = 1; //leave marks
        }

    }

}

/* Tracer pre-determined edges:
    trace edges hit-counts; examined edges: & 1111 1110;

 */
void TracerPredtm(u32 predtm_id){
    if (trace_bits){
        trace_bits[predtm_id]++; // like AFL

        trace_bits[predtm_id + MAP_SIZE] &= 254; //edge flag: & 1111 1110: examined

    }
}

/*
    for saving crashes;
*/
void CrasherPredtm(u32 predtm_id){
    if (trace_bits){
        if ((trace_bits[predtm_id + MAP_SIZE] & EDGE_CRASH) == 4){ // crash not examined
            trace_bits[predtm_id + MAP_SIZE] &= 251; //set crash examined 1111 1011
            
            trace_bits[MAP_SIZE + BYTES_FLAGS + FLAG_LOOP] = COND_COVERAGE;
            //exit(COND_COVERAGE);
        }
           
    }
}
/* Trimmer pre-determined edges:
    like AFL
    do AFL stuff
    trace edges hit-counts;
 */
void TrimmerPredtm(u32 predtm_id){
    if (trace_bits){
        trace_bits[predtm_id]++; 
    }
}

/* 
max_map_size: the max number of edges
max_predtm: the largest number of pre-determined edges
indirect_file: path to the file that contains (src_addr  des_addr  id)

  */
void OracleIndirect(u64 src_addr, u64 des_addr, u32 max_map_size, u32 max_predtm, const char* indirect_file){

    auto itdl = indirect_ids.find(EDGE(src_addr, des_addr)); 
    if (itdl != indirect_ids.end()){ // already exist
        u32 inID = (*itdl).second;
        if ( (trace_bits[inID + MAP_SIZE]& EDGE_MARK) == 0){ //marked
            trace_bits[inID] = 1; //leave a mark
        }
        return;
    }

    /* indirect edge does not exist --> examine a new indirect edge;*/
    // in case some instrumentation of indirect edges are before forkserver
    // if (cur_max_id < (max_predtm - 1)) cur_max_id = max_predtm - 1;

    //assign a new id for the edge
    cur_max_id++;
    if (cur_max_id >= max_map_size) cur_max_id = max_map_size - 1; //don't overflow

    /* in case the target binary forks a new child */
    if ( (trace_bits[cur_max_id + MAP_SIZE] & EDGE_COVERED) == 0 ) return; // examined

    trace_bits[cur_max_id + MAP_SIZE] &= 252; //set examined and marked, 1111 1100
    trace_bits[cur_max_id] = 1; //leave a mark

    //indirect_ids.insert(make_pair(EDGE(src_addr, des_addr), cur_max_id));
    //save new edge into a file, for recovering fuzzing
    ofstream indaddrs;
    indaddrs.open (indirect_file, ios::out | ios::app | ios::binary); //write file
    if(indaddrs.is_open()){
        indaddrs << src_addr << " " << des_addr << " " << cur_max_id << endl; 
        indaddrs.close();
    }

    /* in case the target binary forks a new child */
    trace_bits[MAP_SIZE + BYTES_FLAGS + FLAG_LOOP] = INDIRECT_COVERAGE;
    exit(INDIRECT_COVERAGE);    
    
}

/* 
max_map_size: the max number of edges
max_predtm: the largest number of pre-determined edges
indirect_file: path to the file that contains (src_addr  des_addr  id)

  */
void TracerIndirect(u64 src_addr, u64 des_addr, u32 max_map_size, u32 max_predtm, const char* indirect_file){
    // should run forkserver each time; for getting the latest indirect_ids
    if (!indirect_ids.empty()){ 
        auto itdl = indirect_ids.find(EDGE(src_addr, des_addr));
        if (itdl != indirect_ids.end()){ // already exist
            if(trace_bits) {
                u32 inID = (*itdl).second;
                trace_bits[inID]++;
            }
            return;
        }
        
    }
    
    
    /* indirect edge does not exist --> examine a new id for indirect edge;
    add it to indirect_ids*/

    //assign a new id for the edge
    cur_max_id++;
    if (cur_max_id >= max_map_size) cur_max_id = max_map_size - 1; //don't overflow

    if(trace_bits) {
        trace_bits[cur_max_id]++;
    }

    /* in case the target binary forks a new child */
    if ( (trace_bits[cur_max_id + MAP_SIZE] & EDGE_COVERED) == 0) return;

    indirect_ids.insert(make_pair(EDGE(src_addr, des_addr), cur_max_id)); // only affect on the current process

    trace_bits[cur_max_id + MAP_SIZE] &= 254; //examined, 1111 1110

    //save new edge into a file, for recovering fuzzing
    ofstream indaddrs;
    indaddrs.open (indirect_file, ios::out | ios::app | ios::binary); //write file
    if(indaddrs.is_open()){
        indaddrs << src_addr << " " << des_addr << " " << cur_max_id << endl; 
        indaddrs.close();
    }
        
    
}

/*
    for saving crashes
*/
void CrasherIndirect(u64 src_addr, u64 des_addr){
    /* it's wierd that the edge has not been examined by tracer or oracle before */
    auto itdl = indirect_ids.find(EDGE(src_addr, des_addr));
    if (itdl != indirect_ids.end()){ //edge exists
        u32 inID = (*itdl).second;
        if ((trace_bits[inID + MAP_SIZE] & EDGE_CRASH) == 4){ //crash not met before
            trace_bits[inID + MAP_SIZE] &= 251; //set crash examined 1111 1011

            trace_bits[MAP_SIZE + BYTES_FLAGS + FLAG_LOOP] = INDIRECT_COVERAGE;
            //exit(INDIRECT_COVERAGE);   
        }
    }
}

/* 
do AFL stuff
  */
void TrimmerIndirect(u64 src_addr, u64 des_addr){
   
    auto itdl = indirect_ids.find(EDGE(src_addr, des_addr));
    if (itdl != indirect_ids.end()){ // already exist
        if(trace_bits) {
            trace_bits[(*itdl).second]++;
        }
    }
     
}

/* instrument at back edges of loops;
   indicate there exists a loop
*/
void TracerLoops(){
    trace_bits[MAP_SIZE + BYTES_FLAGS] = 1; //loop flag; 1: it's a loop
}






