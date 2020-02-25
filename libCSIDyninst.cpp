/* 
    Tracer has to re-run each time because it needs to update makrs and indirect ids for the later instrumentations
*/


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
//u16 cur_mark_id; // the current id for marks

//std::map<u32, u16> all_path_marks; // [predtm_id, mark_id]
std::set<u32> all_path_marks,   //all marks in the program
                cksum_path_marks; // for sorting path cksum; all elements are marks in a path


/* 
    max_predtm: the largest number of pre-determined edges
    indirect_file: this file is used when afl wants to re-run the target and use previous results;
                    it contains three number in a row: (src_addr des_addr id)
    marks_file: marks in the file; [mark_id]
*/
void initAflForkServer(u32 max_predtm, const char* marks_file, const char* indirect_file){
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

    /* for calculating path ids */
    //u32 path_id;
    cksum_path_marks.clear(); //initial; 
    all_path_marks.clear();

    // enter fork() server thyme!
    //int n;
    if( write(FORKSRV_FD+1, &temp_data, 4) !=4 ) {
        perror("Error writting fork server\n");
        return;
    }

    struct stat inbuff;
    /* get the marks saved before */
    u32 tmp_mark_id;
    if (stat(marks_file, &inbuff) == 0){
        ifstream marks_io(marks_file);
        if (marks_io.is_open()){
            while(marks_io >> tmp_mark_id){
                all_path_marks.insert(tmp_mark_id);

            }
            marks_io.close();            
        }
    }

    /*recover indirect ids*/  
    u64 ind_src, ind_des;
    u32 addr_id;
    // the max id of indirect edges while starting fuzzing
    cur_max_id = max_predtm - 1; // the max id of pre-determined edges

    if (stat(indirect_file, &inbuff) == 0){ // file  exists
        ifstream indirect_io (indirect_file); //read file
        if (indirect_io.is_open()){
            while(indirect_io >> ind_src >> ind_des >> addr_id){
                indirect_ids.insert(make_pair(EDGE(ind_src, ind_des), addr_id));
                if (addr_id > cur_max_id) cur_max_id = addr_id;
            }
            indirect_io.close();
        }
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

/* Oracle predetermined edges:
    exit if not examined, add path mark; record path mark for cksum  
    predtm_id: pre-determined id
    marks_file: a file record the marks from edges
*/
void OraclePredtm(u32 predtm_id, const char* marks_file){
    if (trace_bits){
        if (trace_bits[predtm_id + MAP_SIZE] == 255){ // have not been examined;
            trace_bits[predtm_id + MAP_SIZE] = 0; //examined
            // save this ID as a mark to a file
            ofstream marks_io (marks_file, ios::out | ios::app | ios::binary);
            if (marks_io.is_open()){
                marks_io << predtm_id << endl; // use edge id as the mark id
                marks_io.close();
            }
            exit(COND_COVERAGE);
        }
        
        // examined
        //trace_bits[predtm_id]++; //set but not used for tracing

        if (all_path_marks.count(predtm_id)){ // this edge id has been marked
            if (!cksum_path_marks.count(predtm_id)){ //not in; write to shared memory
                cksum_path_marks.insert(predtm_id); // insert the id for calculating path cksum
                u32 *trace32 = (u32*)(trace_bits + 2 * MAP_SIZE); // point to the memory of path checksum
                int i = 0;
                for (auto insert_iter = cksum_path_marks.begin(); insert_iter!= cksum_path_marks.end(); ++insert_iter){
                    trace32[i] = *insert_iter;
                    i++;
                    if (i >= SIZE_CKSUM_PATH) break;  //don't overflow
                }
            }
        }
    }

}

/* Tracer pre-determined edges:
    trace edges hit-counts; set examined edges to 0;
 */
void TracerPredtm(u32 predtm_id){
    if (trace_bits){
        trace_bits[predtm_id]++; // like AFL

        trace_bits[predtm_id + MAP_SIZE] = 0; //edge flag: set to 0: examined

        if (all_path_marks.count(predtm_id)){ // this edge id has been marked
            if (!cksum_path_marks.count(predtm_id)){ //not in; write to shared memory
                cksum_path_marks.insert(predtm_id); // insert the id for calculating path cksum
                u32 *trace32 = (u32*)(trace_bits + 2 * MAP_SIZE); // point to the memory of path checksum
                int i = 0;
                for (auto insert_iter = cksum_path_marks.begin(); insert_iter!= cksum_path_marks.end(); ++insert_iter){
                    trace32[i] = *insert_iter;
                    i++;
                    if (i >= SIZE_CKSUM_PATH) break;  //don't overflow
                }
            } 
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
void OracleIndirect(u64 src_addr, u64 des_addr, u32 max_map_size, u32 max_predtm, const char* indirect_file, const char* marks_file){

    if (!indirect_ids.empty()){
        if (indirect_ids.count(EDGE(src_addr, des_addr))){ // already exist
            auto itdl = indirect_ids.find(EDGE(src_addr, des_addr));
            u32 inID = (*itdl).second;
            //trace_bits[(*itdl).second] ++; //set but not used for tracing

            if (all_path_marks.count(inID)){ // this edge id has been marked
                if (!cksum_path_marks.count(inID)){ //not in; write to shared memory
                    cksum_path_marks.insert(inID); // insert the id for calculating path cksum
                    u32 *trace32 = (u32*)(trace_bits + 2 * MAP_SIZE); // point to the memory of path checksum
                    int i = 0;
                    for (auto insert_iter = cksum_path_marks.begin(); insert_iter!= cksum_path_marks.end(); ++insert_iter){
                        trace32[i] = *insert_iter;
                        i++;
                        if (i >= SIZE_CKSUM_PATH) break;  //don't overflow
                    }
                }
            }
            return;
        }

    }
    
    
    /* indirect edge does not exist --> find a new indirect edge;*/

    // in case some instrumentation of indirect edges are before forkserver
    if (cur_max_id < (max_predtm - 1)) cur_max_id = max_predtm - 1;

    //assign a new id for the edge
    cur_max_id++;
    if (cur_max_id >= max_map_size) cur_max_id = max_map_size - 1; //don't overflow

    indirect_ids.insert(make_pair(EDGE(src_addr, des_addr), cur_max_id));
    // //save new edge into a file, for recovering fuzzing
    // ofstream indaddrs;
    // indaddrs.open (indirect_file, ios::out | ios::app | ios::binary); //write file
    // if(indaddrs.is_open()){
    //     indaddrs << src_addr << " " << des_addr << " " << cur_max_id << endl; 
    //     indaddrs.close();
    // }

    // save the path mark to file
    ofstream marks_io (marks_file, ios::out | ios::app | ios::binary);
    if (marks_io.is_open()){
        marks_io << cur_max_id << endl; // use edge id as the mark id
        marks_io.close();
    }

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
                /* for calculating path identifier */
                if (all_path_marks.count(inID)){ // this edge id has been marked
                    if (!cksum_path_marks.count(inID)){ //not in; write to shared memory
                        cksum_path_marks.insert(inID); // insert the id for calculating path cksum
                        u32 *trace32 = (u32*)(trace_bits + 2 * MAP_SIZE); // point to the memory of path checksum
                        int i = 0;
                        for (auto insert_iter = cksum_path_marks.begin(); insert_iter!= cksum_path_marks.end(); ++insert_iter){
                            trace32[i] = *insert_iter;
                            i++;
                            if (i >= SIZE_CKSUM_PATH) break;  //don't overflow
                        }
                    }
                }
            }
            return;
        }
        
    }
    
    /* indirect edge does not exist --> find a new id for indirect edge;
    add it to indirect_ids*/

    // in case some instrumentations are before forkserver
    if (cur_max_id < (max_predtm - 1)) cur_max_id = max_predtm - 1;

    //assign a new id for the edge
    cur_max_id++;
    if (cur_max_id >= max_map_size) cur_max_id = max_map_size - 1; //don't overflow

    indirect_ids.insert(make_pair(EDGE(src_addr, des_addr), cur_max_id)); // only affect on the current process

    if(trace_bits) {
        trace_bits[cur_max_id]++;
    }
    //save new edge into a file, for recovering fuzzing

    ofstream indaddrs;
    indaddrs.open (indirect_file, ios::out | ios::app | ios::binary); //write file
    if(indaddrs.is_open()){
        indaddrs << src_addr << " " << des_addr << " " << cur_max_id << endl; 
        indaddrs.close();
    }
        
    
}


/* do AFL stuff
max_map_size: the max number of edges
max_predtm: the largest number of pre-determined edges
indirect_file: path to the file that contains (src_addr  des_addr  id)

  */
void TrimmerIndirect(u64 src_addr, u64 des_addr){
    if (!indirect_ids.empty()){ 
        auto itdl = indirect_ids.find(EDGE(src_addr, des_addr));
        if (itdl != indirect_ids.end()){ // already exist
            if(trace_bits) {
                trace_bits[(*itdl).second]++;
            }
            return;
        }
        
    }
     
}

/* instrument at back edges of loops;
   indicate there exists a loop
*/
void TracerLoops(){
    trace_bits[2 * MAP_SIZE + BYTES_CKSUM_PATH] = 1; //loop flag; it's a loop
}

