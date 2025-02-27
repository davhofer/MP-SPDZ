#ifndef CONSISTENCY_UTILS_H_
#define CONSISTENCY_UTILS_H_

// avoid namespace clash
#define byte blst_byte
#include "ckzg.h"
#include "common/lincomb.h"  
#include "common/utils.h"  
#undef byte

#include "Protocols/Rep3Share.h"
#include "Math/gfp.h"
#include "Processor/Input.h"
// #include "Tools/octetStream.h"

template<class T>
T share_new_value(int input_party, typename T::clear value, Input<T> &input_protocol, Player &parties) {
    input_protocol.reset_all(parties);
    if (input_party == parties.my_num()) {
        input_protocol.add_mine(value);
    } else {
        input_protocol.add_other(input_party);
    }
    input_protocol.exchange();
    //  TODO: check?
    return input_protocol.finalize(input_party);
}


// TODO: rename as convert_value, and use generic argument names "from" and "to"
void convert_value(blst_fr *to, const gfp_<0, 4> *from);

void convert_value(gfp_<0, 4> *to, const blst_fr *from);

void convert_value(gfp_<0, 4> *to, const blst_fp *from);

void convert_value(g1_t *to, const fr_t *from);

bool read_single_hex_string(ifstream &input_file, octetStream &os);

std::pair<std::vector<fr_t>, fr_t> polynomial_division_X_minus_c(const std::vector<fr_t>& poly, fr_t c);

#endif
