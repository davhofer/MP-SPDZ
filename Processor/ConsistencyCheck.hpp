#ifndef CONSISTENCY_CHECK_CPP_
#define CONSISTENCY_CHECK_CPP_

#include "Protocols/ShamirShare.h"
#include "Processor/ConsistencyCheck.h"

#include "Math/Integer.h"
#include "Networking/Player.h"

#include "Protocols/ProtocolSet.h"
#include "Tools/Bundle.h"
#include "Protocols/ReplicatedInput.h"

#include "Processor/SpecificPrivateOutput.h"
#include "Math/gfp.hpp"

#include "Processor/P381Element.h"

#include <iostream>
#include <fstream>
#include <vector>


//////////////////////////////////////////////////////////////////////////////////


#define NO_SECURITY_CHECK

#define NO_MIXED_CIRCUITS





template<class T, class CurveShare, class ScalarShare>
bool check_commitment(
    const std::vector<int> &args, 
    MemoryPart<T> &memory,
    std::vector<std::vector<gfp_<0, 4>>> &clear_inputs,
    KZGCommitmentScheme &commitment_scheme,
    ConsistencyCheck<T, KZGCommitmentScheme> *cc
) {
    std::cout << "KZG based check_commitment\n";
    int my_num = cc->P->my_num();

    // for benchmarking: party 0 is always the prover

    bool is_benchmark_prover = my_num == 0;


    size_t total_data_sent = 0;
    size_t data_start = 0;
    size_t data_end = 0;

    double t_total = 0;


    size_t n = args.size()/3;

    // prepare verification inputs
    std::vector<ScalarShare> omega_shares(n);
    std::vector<typename KZGCommitmentScheme::CurvePoint> omega_commitments(n), commitments(n);
    std::vector<typename KZGCommitmentScheme::CurvePoint::Scalar> rhos(n), prover_omegas(n);


    // NOTE: we assume all parties already have the commitments/secret shares
    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == args[3*i];

        // TODO: is allocating a new octetStream for every iteration too inefficient?
        octetStream os;
        typename KZGCommitmentScheme::CurvePoint C;
        if (is_prover) {
            // TODO: add field for commitment input
            bool res = read_single_hex_string(*cc->commitment_input, os);
            assert(res);
            cc->P->send_all(os);
            C.unpack(os);
        } else {
            cc->P->receive_player(args[3*i], os);
            C.unpack(os);
        }
        commitments[i] = C;
        std::cout << "\nLoaded input commitment:\n" << C << std::endl;
    }


    // 1. sample and share all masking values and masking commitments
    // -> depends on who the prover is


    // prepare input protocol (for secret-sharing values with other parties)
    cc->scalar_input_protocol.reset_all(*cc->P);

    // sample omegas, commit to omegas, send commitment and secret-share omega
    
    // TODO: can we do the sending/receiving of commitments more efficiently?
    // => can pack all commitments into one octetStream. but how to decode them so we still know which belongs to what?



    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == args[3*i];
        typename KZGCommitmentScheme::CurvePoint c_omega;
        octetStream os;
        if (is_prover) {

            Timer t;
            t.start();

            std::vector<typename KZGCommitmentScheme::CurvePoint::Scalar> omega(1);
            omega[0].randomize(cc->secure_prng);
            prover_omegas[i] = omega[0];
            c_omega = commitment_scheme.commit(omega);

            auto tmp = t.elapsed();
            t_total += tmp;
            std::cout << "sampling random omega took " << tmp << " seconds\n";
            t.stop();

            data_start = cc->P->get_sent();

            c_omega.pack(os);
            cc->P->send_all(os);

            data_end = cc->P->get_sent();
            total_data_sent += data_end - data_start;

            cc->scalar_input_protocol.add_mine(omega[0]);
        } else {

            cc->P->receive_player(args[3*i], os);
            c_omega.unpack(os);

            cc->scalar_input_protocol.add_other(args[3*i]);
        }
        omega_commitments[i] = c_omega;
    }



    data_start = cc->P->get_sent();

    cc->scalar_input_protocol.exchange();

    data_end = cc->P->get_sent();
    total_data_sent += data_end - data_start;

    
    for (size_t i=0;i<n;i++) {
        omega_shares[i] = cc->scalar_input_protocol.finalize(args[3*i]);
    }


    // 2. sample random challenge beta
    // 3. compute and open all evaluations rho
    //
    //
    // For benchmarking: the following is verifier computation!
    data_start = cc->P->get_sent();
    Timer t;
    t.start();

    typename KZGCommitmentScheme::CurvePoint::Scalar beta; // use a single beta, for batch verification
    beta.randomize(cc->shared_prng);


    data_end = cc->P->get_sent();
    total_data_sent += data_end - data_start;

    typename KZGCommitmentScheme::CurvePoint::Field beta_fr;
    convert_value(&beta_fr, &beta);


    // TODO: add field for share memory and clear memory
    std::vector<ScalarShare> rhos_shared(n);
    for (size_t i=0;i<n;i++) {
        ScalarShare rho_shared;
        rho_shared += omega_shares[i];

        int start_addr = args[3*i+1];
        int length = args[3*i+2];

        std::cout << "POLY EVAL\n";
        std::cout << "length: " << length << std::endl;
        std::cout << "beta: " << beta << std::endl;
        // TODO: start with 1 or beta?
        typename KZGCommitmentScheme::CurvePoint::Scalar current_beta(1); // beta;
        for (int j = 0; j < length; j++) { // can we parallelize this?
            rho_shared += memory[start_addr + j] * current_beta;
            current_beta = current_beta * beta;
        }

        // Scalar rho = scalar_opening_protocol.open(rho_shared);
        rhos_shared[i] = rho_shared;
    }

    if (!is_benchmark_prover) { 
        auto tmp = t.elapsed();
        t_total += tmp;
        std::cout << "sampling beta & polynomial evaluation took " << tmp << " seconds\n";
    }
    t.stop();

    data_start = cc->P->get_sent();

    // open all shares at once
    cc->scalar_opening_protocol.POpen(rhos, rhos_shared, *cc->P);
    // TODO: exchange all at once?
    // is this correct?
    cc->scalar_opening_protocol.Check(*cc->P);

    data_end = cc->P->get_sent();
    if (!is_benchmark_prover) total_data_sent += data_end - data_start;

    std::cout << "opened rho: " << rhos[0] << std::endl;
    /*
 * 4. prover generates a proof pi <- PC.Prove(c + c_omega, Poly[x] + Poly[omega], beta, rho), and sends pi to all verifiers
 * 5. verifiers run PC.Check with same inputs (except Poly of x and omega), to make sure evaluation proof is correct
    */

    std::vector<typename KZGCommitmentScheme::CurvePoint::Scalar> verify_rhos;
    std::vector<typename KZGCommitmentScheme::CurvePoint> verify_commitments, verify_proofs;


    // 4. compute and share all proofs pi 
    // -> depends on who the prover is
    // also prepare the inputs for batch verification

    int clear_input_ptr = -1;



    for (size_t i=0;i<n;i++) {
        int prover = args[3*i];
        int input_size = args[3*i+2];

        // => we use poly. commit scheme here 
        typename KZGCommitmentScheme::CurvePoint c = commitments[i] + omega_commitments[i];
        // blst_p1_add(&c, &commitments[i], &omega_commitments[i]);
        octetStream os;
        typename KZGCommitmentScheme::CurvePoint pi;
        if (prover == my_num) {
            std::cout << "I AM PROVER\n";

            Timer t;
            t.start();
            clear_input_ptr++;


            // compute and send proof
            std::vector<typename KZGCommitmentScheme::CurvePoint::Field> input_poly(input_size);

            // TODO: correct?
            typename KZGCommitmentScheme::CurvePoint::Scalar coeff0 = clear_inputs[clear_input_ptr][0] + prover_omegas[i];


            convert_value(&input_poly[0], &coeff0);


            for (int j=1; j < input_size; j++) {
                convert_value(&input_poly[j], &clear_inputs[clear_input_ptr][j]);
            }


            typename KZGCommitmentScheme::CurvePoint::Field rho_fr;
            convert_value(&rho_fr, &rhos[i]);

            pi = commitment_scheme.prove(c.get_point(), input_poly, beta_fr, rho_fr);

            auto tmp = t.elapsed();
            t_total += tmp;
            t.stop();
            std::cout << "computing proof (polynomial division) took " << tmp << " seconds\n";

            data_start = cc->P->get_sent();

            pi.pack(os);
            cc->P->send_all(os);

            data_end = cc->P->get_sent();
            total_data_sent += data_end - data_start;

        } else {
            std::cout << "I AM VERIFIER\n";
            // set up verification input
            verify_commitments.push_back(c);
            verify_rhos.push_back(rhos[i]);
            cc->P->receive_player(prover, os);
            pi.unpack(os);
            verify_proofs.push_back(pi);
        }

        /*
         * Commented out for benchmarking
        typename KZGCommitmentScheme::CurvePoint p_default;
        if (pi == p_default) {
            std::cout << "\nCommitmentScheme.prove failed, evaluation invalid.\n";
            return false;
        }
        */

    }



    if (is_benchmark_prover) {
        std::cout << "DATA:check:" << total_data_sent << std::endl;
        std::cout << "TIMER:check:" << t_total << std::endl;
    }

    int n_verify = verify_commitments.size();
    if (n_verify == 0) return true;

    // 5. a) if we only have one commitment to verify, do it directly
    bool result;
    if (n_verify == 1) {
        std::cout << "\nperforming single verification...\n";
        typename KZGCommitmentScheme::CurvePoint::Field rho_fr;
        convert_value(&rho_fr, &verify_rhos[0]);

        Timer t;
        t.start();

        result = commitment_scheme.verify(verify_commitments[0].get_point(), beta_fr, rho_fr, verify_proofs[0].get_point());

        auto tmp = t.elapsed();
        t_total += tmp;
        t.stop();
        std::cout << "verifying the proof took " << tmp << " seconds\n";

    } else {
        // 5. b) otherwise perform batched verification
        std::cout << "\nperforming batch verification...\n";

        // TODO: might want to move this INSIDE of KZG commitment scheme 
        // since it is specific to that scheme

        typename KZGCommitmentScheme::CurvePoint::Scalar current_gamma(1), gamma, rho_tilde(0);

        Timer t;
        t.start();

        gamma.randomize(cc->secure_prng);

        typename KZGCommitmentScheme::CurvePoint c_tilde(G1_IDENTITY), pi_tilde(G1_IDENTITY);
        for (size_t i = 0; i < verify_commitments.size(); i++) {
            c_tilde = c_tilde + verify_commitments[i] * current_gamma; 
            pi_tilde = pi_tilde + verify_proofs[i] * current_gamma; 
            rho_tilde = rho_tilde + verify_rhos[i] * current_gamma;

            current_gamma = current_gamma * gamma;
        }

        typename KZGCommitmentScheme::CurvePoint::Field rho_tilde_fr;
        convert_value(&rho_tilde_fr, &rho_tilde);
        result = commitment_scheme.verify(c_tilde.get_point(), beta_fr, rho_tilde_fr, pi_tilde.get_point());

        auto tmp = t.elapsed();
        t_total += tmp;
        t.stop();
        std::cout << "verifying the proofs took " << tmp << " seconds\n";

    }

    if (!is_benchmark_prover) {
        std::cout << "DATA:check:" << total_data_sent << std::endl;
        std::cout << "TIMER:check:" << t_total << std::endl;
    }

    return result;
}

template<class T, class CurveShare, class ScalarShare>
bool check_commitment(
    const std::vector<int> &args, 
    MemoryPart<T> &memory,
    std::vector<std::vector<gfp_<0, 4>>> &clear_inputs,
    PedVecCommitmentScheme &commitment_scheme,
    ConsistencyCheck<T, PedVecCommitmentScheme> *cc
) {
    (void) commitment_scheme;
    (void) clear_inputs;
    std::cout << "PedersenVector based check_commitment\n";

    int my_num = cc->P->my_num();

    // for benchmarking: party 0 is always the prover

    bool is_benchmark_prover = my_num == 0;

    size_t total_data_sent = 0;

    double t_total = 0;


    // in pedersen vector commitments, there is no special prover work, verifiers just recompute the commitment
    if (is_benchmark_prover) {
        std::cout << "DATA:check:" << total_data_sent << std::endl;
        std::cout << "TIMER:check:" << t_total << std::endl;
    }


    size_t n = args.size()/3;

    for (size_t i=0;i<n;i++) {
        int prover = args[3*i];
        bool is_prover = my_num == prover;

        // TODO: is allocating a new octetStream for every iteration too inefficient?
        // NOTE: for benchmarking, we're assuming that the verifiers already have the commitments and the the shares
        octetStream os;
        typename PedVecCommitmentScheme::CurvePoint C;
        if (is_prover) {
            // TODO: add field for commitment input
            bool res = read_single_hex_string(*cc->commitment_input, os);
            assert(res);
            cc->P->send_all(os);
        } else {
            cc->P->receive_player(prover, os);
        }
        C.unpack(os);
        std::cout << "\nLoaded input commitment:\n" << C << std::endl;

        // TODO: check
        int share_addr = args[3*i+1];
        int len = args[3*i+2];
        
        Timer t;
        t.start();

        // TODO: use cc->commit
        std::vector<T> shares(len);
        for(int j=0;j<len;j++) shares[j] = memory[share_addr + j];

        typename PedVecCommitmentScheme::CurvePoint C_verify = cc->commit_secret(shares);

        t_total += t.elapsed();
        t.stop();

        /*
         * commented out for benchmarking
        if (C != C_verify) {
            return false;
        }
        */
    }
    if (!is_benchmark_prover) {
        std::cout << "DATA:check:" << total_data_sent << std::endl;
        std::cout << "TIMER:check:" << t_total << std::endl;
    }
    return true;
}


///////////////////////////////////////////////////////////////////////////////////////////
/// Constructors
///////////////////////////////////////////////////////////////////////////////////////////

template <class T, class CommitmentScheme>
ConsistencyCheck<T, CommitmentScheme>::ConsistencyCheck() {
}

template <class T, class CommitmentScheme>
ConsistencyCheck<T, CommitmentScheme>::~ConsistencyCheck() {
}

template <class T, class CommitmentScheme>
ConsistencyCheck<T, CommitmentScheme>::ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<typename T::clear> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai) {
    (void) sp;
    (void) player;
    (void) processor_S;
    (void) processor_C;
    (void) processor_commitment_input;
    (void) alphai;
}


template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp, Player *player, StackedVector<Rep3Share<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
    : random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "Rep3Share CC initializer\n";
    (void) alphai;
    // TODO: could this be made Share-type agnostic? fully templated? i.e. replace Rep3Share with SecretShare, anything that won't work?

 // TODO: curve init required? think not

  // (old) here we only need to initialize the curve params, not the field, because
  // the field is the same as the scalar field used by MPC and already
  // initialized!
  
  typename ScalarShare::mac_key_type input_mac_key;
  ScalarShare::read_or_generate_mac_key("", *P, input_mac_key);
  scalar_opening_protocol = (typename ScalarShare::MAC_Check)(input_mac_key);

  sig_pk_protocol = (typename PkShare::MAC_Check)(input_mac_key);
  sig_protocol = (typename SigShare::MAC_Check)(input_mac_key);

  // typename Rep3Share<typename CurvePoint>::mac_key_type input_mac_key2;
  // TODO: reset to use input_amc_key2: typename CurveShare::mac_key_type input_mac_key2;
  // Rep3Share<typename CurvePoint>::read_or_generate_mac_key("", P,
  //                                                    input_mac_key2);
  CurveShare::read_or_generate_mac_key("", *P, input_mac_key); // key2
  // opening_protocol =
  //     (typename Rep3Share<typename CurvePoint>::MAC_Check)(input_mac_key2);
  opening_protocol =
      (typename CurveShare::MAC_Check)(input_mac_key); // key2

  mac_key = input_mac_key; // key2
    //

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  // P377Element::Scalar::init_field(gfp_<0, 4>::pr());

  //  bigint::init_thread();
  // sp.P.num_players();

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}


///////////////////////////////////////////////////////////////////////////////////////////
/// setup 
///////////////////////////////////////////////////////////////////////////////////////////

template <class T, class CommitmentScheme> 
void ConsistencyCheck<T, CommitmentScheme>::setup(size_t d) {
    (void) d;
}

template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}

// TODO: specific implementations...
template <class CommitmentScheme> 
void ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}


///////////////////////////////////////////////////////////////////////////////////////////
/// commit_secret
///////////////////////////////////////////////////////////////////////////////////////////
template <class T, class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<T, CommitmentScheme>::commit_secret(std::vector<T> &shares) {
    (void) shares;
    return {};
}


template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<Rep3Share<gfp_<0, 4>>> &shares) {
    std::cout << "Rep3Share CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "ERROR: Setup not performed yet, must be done first!\n";
        return {};
    }

    size_t sent_before = P->get_sent();
    Timer t;
    t.start();


    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    std::vector<typename CurvePoint::Scalar> coeffs1(shares.size()), coeffs2(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        coeffs1[i] = shares[i].get()[0];
        coeffs2[i] = shares[i].get()[1];
    }



    array<CurvePoint, 2> committed_shares = {
        commitment_scheme.commit(coeffs1), 
        commitment_scheme.commit(coeffs2)
    };


    CurveShare C_shared = CurveShare(committed_shares); // Rep3Share<CurvePoint>
    CurvePoint C = opening_protocol.open(C_shared, *P);
    opening_protocol.Check(*P);

    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    size_t sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}




///////////////////////////////////////////////////////////////////////////////////////////
/// sign_commitment
///////////////////////////////////////////////////////////////////////////////////////////

template <class CommitmentScheme>
void ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    sig_sk = random_protocol.get_random();

    // extract sk share values, 
    Scalar ps1 = sig_sk.get()[0];
    Scalar ps2 = sig_sk.get()[1];

    blst_scalar sc1, sc2;
    convert_value(&sc1, &ps1);
    convert_value(&sc2, &ps2);
    
    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p1, p2;
    blst_sk_to_pk_in_g1(&p1, &sc1); 
    blst_sk_to_pk_in_g1(&p2, &sc2); 
    P381Element pk1(p1), pk2(p2);

    // reconstruct pk shares, open pk
    array<P381Element, 2> pk_array = {
        p1, 
        p2 
    };

    PkShare pk_shared = PkShare(pk_array);
    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);


     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);
    // extract sk share values,
    //  enter into blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash, const blst_scalar *SK);
    // reconstruct signature shares, open signature
    // print signature
    Scalar ps1 = sig_sk.get()[0];
    Scalar ps2 = sig_sk.get()[1];

    blst_scalar sc1, sc2;
    convert_value(&sc1, &ps1);
    convert_value(&sc2, &ps2);

    g2_t p1;
    blst_sign_pk_in_g1(&p1, &hashed, &sc1);

    g2_t p2;
    blst_sign_pk_in_g1(&p2, &hashed, &sc2);



    P381ElementG2 sig1(p1), sig2(p2);

    // reconstruct pk shares, open pk
    array<P381ElementG2, 2> sig_array = {
        sig1, 
        sig2 
    };

    SigShare sig_shared = SigShare(sig_array);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);

    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}

// TODO: specific implementations...


///////////////////////////////////////////////////////////////////////////////////////////
/// check_batch
///////////////////////////////////////////////////////////////////////////////////////////
template <class T, class CommitmentScheme>
bool ConsistencyCheck<T, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
  (void)args;
  (void) memory;
  return false;
}

// NOTE: only the prover requires clear_input
template <class CommitmentScheme>
bool ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "Rep3Share CC.check_batch\n";
    std::cout << std::endl;

    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }


    // args: (prover_num, address, length)


    bool res = check_commitment<Rep3Share<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;
}



////////////////////////////////////////////////////////////////////////////////////// end
////////////////////////////////////////////////////////////////////////////////////// end
////////////////////////////////////////////////////////////////////////////////////// end
////////////////////////////////////////////////////////////////////////////////////// end
////////////////////////////////////////////////////////////////////////////////////// end


//////////////////////////////////////////////////////////////////
///
///
/// MASCOT (SPDZ) SHARE
///
///
//////////////////////////////////////////////////////////////////

template <class CommitmentScheme>
ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<Share<gfp_<0, 4>>> *sp, Player *player, StackedVector<Share<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
    : opening_protocol(alphai), scalar_opening_protocol(alphai), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "SPDZ CC initializer\n";

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

    secure_prng.ReSeed();
    shared_prng.SeedGlobally(*P, false);

    // opening_protocol.setup(*P);
    // scalar_opening_protocol.setup(*P);
    // at this point, MC.coordinator != 0
}


template <class CommitmentScheme>
ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
// TODO: specific implementations...
template <class CommitmentScheme> 
void ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);

    sig_pk_protocol.setup(*P);
    sig_protocol.setup(*P);
    // opening_protocol.setup(*P);

    setup_signing_keys();
    setup_complete = true;



}


template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<Share<gfp_<0, 4>>> &shares) {
    std::cout << "SPDZ CC.commit_secret()\n";

    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    std::vector<typename CurvePoint::Scalar> inner_shares(shares.size()), inner_macs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        // TODO: can this conversion be faster?
        inner_shares[i] = shares[i].get_share();
        inner_macs[i] = shares[i].get_mac();
    }

    CurvePoint C_inner_share = commitment_scheme.commit(inner_shares);
    CurvePoint C_mac = commitment_scheme.commit(inner_macs);

    CurveShare C_shared;
    C_shared.set_share(C_inner_share);
    C_shared.set_mac(C_mac);


    /*
    opening_protocol.init_open(*P);
    opening_protocol.prepare_open(C_shared);
    opening_protocol.exchange(*P);

    CurvePoint C = opening_protocol.finalize_open();
    */
    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: .Check
    opening_protocol.Check(*P);

    // TODO: enable to check macs
    // at this point, MC.coordinator == 0 ??
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}



template <class CommitmentScheme>
bool ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "SPDZ CC.check_batch\n";

    // TODO: each verifier groups together all proofs for which it is a verifier and not prover, and verifies them at once

    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)

    bool res = check_commitment<Share<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;
}

template <class CommitmentScheme>
void ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    //
    //
    
    scalar_input_protocol.reset_all(*P);
    Scalar insecure_sk(3);
    if (P->my_num() == 0)
        scalar_input_protocol.add_mine(insecure_sk);
    else
        scalar_input_protocol.add_other(0);
    scalar_input_protocol.exchange();
    
    sig_sk = scalar_input_protocol.finalize(0);
    // sig_sk = random_protocol.get_random();

    // extract sk share values, 
    Scalar sk_share = sig_sk.get_share();
    Scalar sk_mac = sig_sk.get_mac();

    blst_scalar sc_share, sc_mac;
    convert_value(&sc_share, &sk_share);
    convert_value(&sc_mac, &sk_mac);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p1, p2;
    blst_sk_to_pk_in_g1(&p1, &sc_share); 
    blst_sk_to_pk_in_g1(&p2, &sc_mac); 
    P381Element pk1(p1), pk2(p2);

    // reconstruct pk shares, open pk
    PkShare pk_shared;
    pk_shared.set_share(pk1);
    pk_shared.set_mac(pk2);

    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    // TODO: .Check
    // std::cout << "sig_pk_protocol.Check\n";
    // std::cout << "probing: " << sig_protocol.probe() << std::endl;
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    // extract sk share values,
    //  enter into blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash, const blst_scalar *SK);
    // reconstruct signature shares, open signature
    // print signature
    Scalar sk_share = sig_sk.get_share();
    Scalar sk_mac = sig_sk.get_mac();

    blst_scalar sc_share, sc_mac;
    convert_value(&sc_share, &sk_share);
    convert_value(&sc_mac, &sk_mac);

    g2_t p1, p2;
    blst_sign_pk_in_g1(&p1, &hashed, &sc_share);
    blst_sign_pk_in_g1(&p2, &hashed, &sc_mac);

    P381ElementG2 sig_share(p1), sig_mac(p2);

    SigShare sig_shared;
    sig_shared.set_share(sig_share);
    sig_shared.set_mac(sig_mac);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);
    // TODO: .Check
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}

//////////////////////////////////////////////////////////////////////////////
///
///
/// SpdzWise (SY) Rep Field Share 
///
///
//////////////////////////////////////////////////////////////////////////////

// conditional compilation
#ifdef PROTOCOLS_SPDZWISESHARE_H_
#ifdef PROTOCOLS_MALICIOUSREP3SHARE_H_
template <class CommitmentScheme>
ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<SpdzWiseRepFieldShare<gfp_<0, 4>>> *sp, Player *player, StackedVector<SpdzWiseRepFieldShare<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
// TODO: how to initialize opening protocol??
    : opening_protocol(alphai), scalar_opening_protocol(alphai), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "SpdzWiseRepFieldShare CC initializer\n";
    (void) alphai;

    DataPositions dp;
    Preprocessing<SpdzWiseRepFieldShare<gfp_<0, 4>>> preprocessing_instance(dp);
    random_protocol.init(preprocessing_instance, scalar_opening_protocol);

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}
template <class CommitmentScheme>
ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
template <class CommitmentScheme> 
void ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}
template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<SpdzWiseRepFieldShare<gfp_<0, 4>>> &shares) {
    std::cout << "SpdzWiseRepFieldShare CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    std::vector<typename CurvePoint::Scalar> coeffs1(shares.size()), coeffs2(shares.size()), macs1(shares.size()), macs2(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        MaliciousRep3Share<gfp_<0, 4>> share = shares[i].get_share();
        MaliciousRep3Share<gfp_<0, 4>> mac = shares[i].get_mac();

        const std::array<Scalar, 2> share_parts = share.get();
        const std::array<Scalar, 2> mac_parts = mac.get();

        coeffs1[i] = share_parts[0];
        coeffs2[i] = share_parts[1];
        macs1[i] = mac_parts[0];
        macs2[i] = mac_parts[1];
    }


    CurvePoint committed_shares1 = commitment_scheme.commit(coeffs1);
    CurvePoint committed_shares2 = commitment_scheme.commit(coeffs2);
    CurvePoint committed_macs1 = commitment_scheme.commit(macs1);
    CurvePoint committed_macs2 = commitment_scheme.commit(macs2);

    std::array<CurvePoint, 2> result_shares_mac, result_shares;
    result_shares[0] = committed_shares1;
    result_shares[1] = committed_shares2;
    result_shares_mac[0] = committed_macs1;
    result_shares_mac[1] = committed_macs2;

    MaliciousRep3Share<CurvePoint> committed_share(result_shares), committed_mac(result_shares_mac);

    // CurveShare C_shared = CurveShare(committed_shares); 

    CurveShare C_shared = CurveShare();
    C_shared.set_share(committed_share);
    C_shared.set_mac(committed_mac);


    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: check for mal. protocols doesnt work yet...
    opening_protocol.Check(*P);
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}
template <class CommitmentScheme>
bool ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "SpdzWiseRepFieldShare CC.check_batch\n";

    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)

    bool res = check_commitment<SpdzWiseRepFieldShare<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );

    return res;
}


template <class CommitmentScheme>
void ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    sig_sk = random_protocol.get_random();

    // extract sk share values, 
    MaliciousRep3Share<Scalar> share = sig_sk.get_share();
    MaliciousRep3Share<Scalar> mac = sig_sk.get_mac();

    const std::array<Scalar, 2> share_parts = share.get();
    const std::array<Scalar, 2> mac_parts = mac.get();

    blst_scalar s1, s2, m1, m2;
    convert_value(&s1, &share_parts[0]);
    convert_value(&s2, &share_parts[1]);
    convert_value(&m1, &mac_parts[0]);
    convert_value(&m2, &mac_parts[1]);

    g1_t ps1, ps2, pm1, pm2;
    blst_sk_to_pk_in_g1(&ps1, &s1); 
    blst_sk_to_pk_in_g1(&ps2, &s2); 
    blst_sk_to_pk_in_g1(&pm1, &m1); 
    blst_sk_to_pk_in_g1(&pm2, &m2); 
    P381Element pk1(ps1), pk2(ps2), pkm1(pm1), pkm2(pm2);


    std::array<P381Element, 2> result_shares_mac, result_shares;
    result_shares[0] = pk1;
    result_shares[1] = pk2;
    result_shares_mac[0] = pkm1;
    result_shares_mac[1] = pkm2;

    MaliciousRep3Share<P381Element> pk_share(result_shares), pk_mac(result_shares_mac);

    PkShare pk_shared = PkShare();
    pk_shared.set_share(pk_share);
    pk_shared.set_mac(pk_mac);


    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);

}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    // extract sk share values,
    //  enter into blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash, const blst_scalar *SK);
    // reconstruct signature shares, open signature
    // print signature
    //
    //


    MaliciousRep3Share<Scalar> share = sig_sk.get_share();
    MaliciousRep3Share<Scalar> mac = sig_sk.get_mac();

    const std::array<Scalar, 2> share_parts = share.get();
    const std::array<Scalar, 2> mac_parts = mac.get();

    blst_scalar s1, s2, m1, m2;
    convert_value(&s1, &share_parts[0]);
    convert_value(&s2, &share_parts[1]);
    convert_value(&m1, &mac_parts[0]);
    convert_value(&m2, &mac_parts[1]);

    g2_t ps1, ps2, pm1, pm2;
    blst_sign_pk_in_g1(&ps1, &hashed, &s1);
    blst_sign_pk_in_g1(&ps2, &hashed, &s2);
    blst_sign_pk_in_g1(&pm1, &hashed, &m1);
    blst_sign_pk_in_g1(&pm2, &hashed, &m2);

    P381ElementG2 sig_share1(ps1), sig_share2(ps2), sig_mac1(pm1), sig_mac2(pm2);

    std::array<P381ElementG2, 2> result_shares_mac, result_shares;
    result_shares[0] = sig_share1;
    result_shares[1] = sig_share2;
    result_shares_mac[0] = sig_mac1;
    result_shares_mac[1] = sig_mac2;

    MaliciousRep3Share<P381ElementG2> sig_share(result_shares), sig_mac(result_shares_mac);

    SigShare s_shared = SigShare();
    s_shared.set_share(sig_share);
    s_shared.set_mac(sig_mac);


    P381ElementG2 signature = sig_protocol.open(s_shared, *P);
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}


#endif
#endif


//////////////////////////////////////////////////////////////////////////////
///
///
/// Temi Share 
///
///
//////////////////////////////////////////////////////////////////////////////

// conditional compilation
#ifdef PROTOCOLS_TEMISHARE_H_
template <class CommitmentScheme>
ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<TemiShare<gfp_<0, 4>>> *sp, Player *player, StackedVector<TemiShare<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
// TODO: how to initialize opening protocol??
    : opening_protocol((typename CurvePoint::Scalar)(3)), scalar_opening_protocol((typename CurvePoint::Scalar)(3)), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "TemiShare CC initializer\n";
    (void) alphai;

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}
template <class CommitmentScheme>
ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
template <class CommitmentScheme> 
void ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}
template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<TemiShare<gfp_<0, 4>>> &shares) {
    std::cout << "TemiShare CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    std::vector<typename CurvePoint::Scalar> coeffs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        coeffs[i] = shares[i];
    }


    CurvePoint committed_shares = commitment_scheme.commit(coeffs);

    CurveShare C_shared(committed_shares);

    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: check for mal. protocols doesnt work yet...
    opening_protocol.Check(*P);
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}
template <class CommitmentScheme>
bool ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "TemiShare CC.check_batch\n";
    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)

    bool res = check_commitment<TemiShare<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;

}


template <class CommitmentScheme>
void ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    sig_sk = random_protocol.get_random();

    // extract sk share values, 
    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p;
    blst_sk_to_pk_in_g1(&p, &sc); 

    P381Element pk_elem(p);

    // reconstruct pk shares, open pk
    PkShare pk_shared(pk_elem);

    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g2_t p2;
    blst_sign_pk_in_g1(&p2, &hashed, &sc);

    P381ElementG2 sig_elem(p2);

    // reconstruct pk shares, open pk
    SigShare sig_shared(sig_elem);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}

#endif

//////////////////////////////////////////////////////////////////////////////
///
///
/// Atlas Share 
///
///
//////////////////////////////////////////////////////////////////////////////

// conditional compilation
#ifdef PROTOCOLS_ATLASSHARE_H_
template <class CommitmentScheme>
ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<AtlasShare<gfp_<0, 4>>> *sp, Player *player, StackedVector<AtlasShare<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
// TODO: how to initialize opening protocol??
    : opening_protocol((typename CurvePoint::Scalar)(3)), scalar_opening_protocol((typename CurvePoint::Scalar)(3)), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "AtlasShare CC initializer\n";
    (void) alphai;

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}
template <class CommitmentScheme>
ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
template <class CommitmentScheme> 
void ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}
template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<AtlasShare<gfp_<0, 4>>> &shares) {
    std::cout << "AtlasShare CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    std::vector<typename CurvePoint::Scalar> coeffs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {

        coeffs[i] = shares[i];
    }


    CurvePoint committed_shares = commitment_scheme.commit(coeffs);

    CurveShare C_shared(committed_shares);

    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: check for mal. protocols doesnt work yet...
    opening_protocol.Check(*P);
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}
template <class CommitmentScheme>
bool ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "AtlasShare CC.check_batch\n";

    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)
    bool res = check_commitment<AtlasShare<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;

}


template <class CommitmentScheme>
void ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    sig_sk = random_protocol.get_random();

    // extract sk share values, 
    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p;
    blst_sk_to_pk_in_g1(&p, &sc); 

    P381Element pk_elem(p);

    // reconstruct pk shares, open pk
    PkShare pk_shared(pk_elem);

    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g2_t p2;
    blst_sign_pk_in_g1(&p2, &hashed, &sc);

    P381ElementG2 sig_elem(p2);

    // reconstruct pk shares, open pk
    SigShare sig_shared(sig_elem);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}


#endif

//////////////////////////////////////////////////////////////////////////////
///
///
/// SpdzWise (SY) Shamir Share 
///
///
//////////////////////////////////////////////////////////////////////////////

// conditional compilation
#ifdef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_

template <class CommitmentScheme>
ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}
template <class CommitmentScheme>
ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<MaliciousShamirShare<gfp_<0, 4>>> *sp, Player *player, StackedVector<MaliciousShamirShare<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
// TODO: how to initialize opening protocol??
    : opening_protocol(CurvePoint()), scalar_opening_protocol((typename CurvePoint::Scalar)(3)), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    std::cout << "MaliciousShamirShare CC initializer\n";
    (void) alphai;

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}
template <class CommitmentScheme>
ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
template <class CommitmentScheme> 
void ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}

template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<MaliciousShamirShare<gfp_<0, 4>>> &shares) {
    std::cout << "MaliciousShamirShare CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    // std::vector<typename CurvePoint::Field> coeffs1(shares.size()), coeffs2(shares.size()), macs1(shares.size()), macs2(shares.size());
    std::vector<typename CurvePoint::Scalar> coeffs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        coeffs[i] = shares[i].get();
    }


    CurvePoint committed_shares = commitment_scheme.commit(coeffs);

    CurveShare C_shared = CurveShare(committed_shares); 

    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: check for mal. protocols doesnt work yet...
    opening_protocol.Check(*P);
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}
template <class CommitmentScheme>
bool ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "MaliciousShamirShare CC.check_batch\n";

    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)

    bool res = check_commitment<MaliciousShamirShare<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;

}



template <class CommitmentScheme>
void ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    sig_sk = random_protocol.get_random();

    // extract sk share values, 
    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p;
    blst_sk_to_pk_in_g1(&p, &sc); 

    P381Element pk_elem(p);

    // reconstruct pk shares, open pk
    PkShare pk_shared(pk_elem);

    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g2_t p2;
    blst_sign_pk_in_g1(&p2, &hashed, &sc);

    P381ElementG2 sig_elem(p2);

    // reconstruct pk shares, open pk
    SigShare sig_shared(sig_elem);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}


template <class CommitmentScheme>
ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<ShamirShare<gfp_<0, 4>>> *sp, Player *player, StackedVector<ShamirShare<gfp_<0, 4>>> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai)
// TODO: how to initialize opening protocol??
    : opening_protocol(CurvePoint()), scalar_opening_protocol((typename CurvePoint::Scalar)(3)), sig_pk_protocol(alphai), sig_protocol(alphai), random_protocol(*player), scalar_input_protocol(*sp), P(player) {
    (void) alphai;

    S_ptr = processor_S;
    C_ptr = processor_C;
    commitment_input = processor_commitment_input;

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}
template <class CommitmentScheme>
ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::~ConsistencyCheck() {
    if(personal_input)
        personal_input.close();
}
template <class CommitmentScheme> 
void ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::setup(size_t d) {
    int n = P->my_num();
    std::string filename = "Player-Data/Input-P" + std::to_string(n) + "-0";
    personal_input = std::ifstream(filename);
    commitment_scheme.setup(d, shared_prng);
    setup_complete = true;
    setup_signing_keys();
}
template <class CommitmentScheme>
typename CommitmentScheme::CurvePoint ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<ShamirShare<gfp_<0, 4>>> &shares) {
    std::cout << "ShamirShare CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;

    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return {};
    }
    auto sent_before = P->get_sent();
    Timer t;
    t.start();

    std::vector<typename CurvePoint::Scalar> coeffs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        coeffs[i] = shares[i].get();
    }


    CurvePoint committed_shares = commitment_scheme.commit(coeffs);

    CurveShare C_shared = CurveShare(committed_shares); 

    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: check for mal. protocols doesnt work yet...
    opening_protocol.Check(*P);
    double duration = t.elapsed();
    t.stop();
    std::cout << "TIMER:commit:"<<duration<<std::endl;
    auto sent_diff = P->get_sent() - sent_before;
    std::cout << "DATA:commit:" << sent_diff << std::endl;

    std::cout << "\nCommitment: ";
    std::cout << C << std::endl << std::endl;

    Timer ts;
    auto signsent = P->get_sent();
    ts.start();
    dist_sign(C);
    double t_sign = ts.elapsed();
    ts.stop();
    std::cout << "TIMER:sign:"<<t_sign<<std::endl;
    signsent = P->get_sent() - signsent;
    std::cout << "DATA:sign:" << signsent << std::endl;

    return C;
}
template <class CommitmentScheme>
bool ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::check_batch(const std::vector<int> &args, MemoryPart<T> &memory) {
    std::cout << "ShamirShare CC.check_batch\n";


    int my_num = P->my_num();

    std::vector<std::vector<gfp_<0, 4>>> clear_inputs;

    for(size_t i=0; i<args.size();i+=3) {
        int input_party = args[i];
        int input_length = args[i+2];
        if (input_party == my_num) {
            clear_inputs.push_back(read_clear_input(personal_input, input_length));
        }
    }

    // args: (prover_num, address, length)


    bool res = check_commitment<ShamirShare<gfp_<0, 4>>, CurveShare, ScalarShare>(
        args,
        memory,
        clear_inputs,
        commitment_scheme,
        this
    );


    return res;

}



template <class CommitmentScheme>
void ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::setup_signing_keys() {
    // randomly sample sk through MPC
    std::cout << "SHAMIR GET RANDOM\n";
    sig_sk = random_protocol.get_random();
    std::cout << "SHAMIR GOT RANDOM\n";
    std::cout << sig_sk << std::endl;

    // extract sk share values, 
    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g1_t p;
    blst_sk_to_pk_in_g1(&p, &sc); 

    P381Element pk_elem(p);

    // reconstruct pk shares, open pk
    PkShare pk_shared(pk_elem);

    sig_pk = sig_pk_protocol.open(pk_shared, *P);
    sig_pk_protocol.Check(*P);
}

template <class CommitmentScheme>
P381ElementG2 ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme>::dist_sign(CurvePoint &p) {
    // convert curve point to g2, by hashing to curve
    octetStream os;
    p.pack(os);
     
    g2_t hashed;
    blst_hash_to_g2(&hashed, os.get_data(), os.get_length(), NULL, 0, NULL, 0);

    Scalar sks = sig_sk;

    blst_scalar sc;
    convert_value(&sc, &sks);

    // enter into blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
    g2_t p2;
    blst_sign_pk_in_g1(&p2, &hashed, &sc);

    P381ElementG2 sig_elem(p2);

    // reconstruct pk shares, open pk
    SigShare sig_shared(sig_elem);

    P381ElementG2 signature = sig_protocol.open(sig_shared, *P);
    sig_protocol.Check(*P);

    std::cout << "\nSignature:\n" << signature << std::endl;

    return signature;
}


#endif


#endif

