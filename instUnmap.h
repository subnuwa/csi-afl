// for unordered map, needs -std=c++11

#include <unordered_map>
#include "types.h"
using namespace std;


struct EDGE
{
    u64 src_addr;
    u64 des_addr;
    EDGE(u64 s, u64 d): src_addr(s), des_addr(d){}

    bool operator==(const EDGE &other) const
    { return (src_addr == other.src_addr
                && des_addr == other.des_addr);
    }
};

//hash function
struct HashEdge{
    std::size_t operator()(const EDGE &edge) const{
        using std::size_t;
        using std::hash;
        size_t res = 17;
        res = res * 31 + hash<u64>()( edge.src_addr );
        res = res * 31 + hash<u64>()( edge.des_addr );
        return res;
    }
};