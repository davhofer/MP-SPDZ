#ifndef CONSISTENCY_CHECK_CPP_
#define CONSISTENCY_CHECK_CPP_

#include "Processor/ConsistencyCheck.h"

#include "Math/Integer.h"
#include "Networking/Player.h"

#include "Protocols/ProtocolSet.h"
#include "Tools/Bundle.h"
#include "Protocols/ReplicatedInput.h"

#include "Processor/SpecificPrivateOutput.h"
#include "Math/gfp.hpp"

#include "Processor/P381Element.h"

// TODO: do we even need to include it here?

#include <assert.h>

// TODO: temporarily activate this for working with maliciously secure shares
#define NO_SECURITY_CHECK

///////////////////////////////////////////////////////////////////////////////////////////
/// Constructors
///////////////////////////////////////////////////////////////////////////////////////////

template <class T, class CommitmentScheme>
ConsistencyCheck<T, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class CommitmentScheme>
ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck() {
}

template <class T, class CommitmentScheme>
ConsistencyCheck<T, CommitmentScheme>::ConsistencyCheck(SubProcessor<T> *sp, Player *player) {
    (void) sp;
    (void) player;
    std::cout << "generic template CC initializer: NOT IMPLEMENTED\n";

    std::cout << "\nINFO:\n";
    std::cout << T::type_string() << std::endl;
}

template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp, Player *player)
    : scalar_input_protocol(*sp), proc(sp), P(player) {
    std::cout << "Rep3Share CC initializer\n";
    // TODO: could this be made Share-type agnostic? fully templated? i.e. replace Rep3Share with SecretShare, anything that won't work?

 // TODO: curve init required? think not

  // (old) here we only need to initialize the curve params, not the field, because
  // the field is the same as the scalar field used by MPC and already
  // initialized!
  
  typename ScalarShare::mac_key_type input_mac_key;
  ScalarShare::read_or_generate_mac_key("", *P, input_mac_key);
  scalar_opening_protocol = (typename ScalarShare::MAC_Check)(input_mac_key);

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

  // P377Element::Scalar::init_field(gfp_<0, 4>::pr());

  //  bigint::init_thread();
  // sp.P.num_players();

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}

template<class T>
typename T::mac_key_type preload_mac_key(Player &P) {
    typename T::mac_key_type input_mac_key;
    T::read_or_generate_mac_key("", P, input_mac_key);
    return input_mac_key;
}


// TODO: need to instantiate opening_protocol right away...
// ./Processor/ConsistencyCheck.h:191:36: note: member is declared here
//  191 |     typename CurveShare::Direct_MC opening_protocol;
//      |                                    ^
// ./Protocols/MAC_Check.h:173:7: note: 'Direct_MAC_Check<Share<P381Element>>' declared here
//  173 | class Direct_MAC_Check: public virtual MAC_Check_<T>
//
// Direct_MAC_Check(const typename T::mac_key_type::Scalar& ai);
//
// => we need a Share<P381Element>::mac_key_type::Scalar ...
//
// => which is actually a P381Element::Scalar
//
// TODO: insecure mac keys (Scalar(3))
template <class CommitmentScheme>
ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<Share<gfp_<0, 4>>> *sp, Player *player)
    : opening_protocol((typename CurvePoint::Scalar)(3)), scalar_opening_protocol((typename CurvePoint::Scalar)(3)), scalar_input_protocol(*sp), proc(sp), P(player) {
    std::cout << "SPDZ CC initializer\n";
    // TODO: could this be made Share-type agnostic? fully templated? i.e. replace Rep3Share with SecretShare, anything that won't work?
    //
 // TODO: curve init required? think not

  // (old) here we only need to initialize the curve params, not the field, because
  // the field is the same as the scalar field used by MPC and already
  // initialized!
  
    /*
  typename ScalarShare::mac_key_type input_mac_key;
  ScalarShare::read_or_generate_mac_key("", *P, input_mac_key);
  scalar_opening_protocol = (typename ScalarShare::MAC_Check)(input_mac_key);
  */

  // typename Rep3Share<typename CurvePoint>::mac_key_type input_mac_key2;
  // TODO: reset to use input_amc_key2: typename CurveShare::mac_key_type input_mac_key2;
  // Rep3Share<typename CurvePoint>::read_or_generate_mac_key("", P,
  //                                                    input_mac_key2);
    /*
  CurveShare::read_or_generate_mac_key("", *P, input_mac_key); // key2
  // opening_protocol =
  //     (typename Rep3Share<typename CurvePoint>::MAC_Check)(input_mac_key2);
  opening_protocol =
      (typename CurveShare::MAC_Check)(input_mac_key); // key2

*/
 // mac_key = input_mac_key; // key2

  // P377Element::Scalar::init_field(gfp_<0, 4>::pr());

  //  bigint::init_thread();
  // sp.P.num_players();

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(*P, false);
}

/*
// TODO: go over this in detail!
// double check this !!!
// make sure sharing works...
template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp)
    : scalar_input_protocol(sp, P), proc(sp) {
    std::cout << "specialized template CC initializer: implemented\n";
    // TODO: could this be made Share-type agnostic? fully templated? i.e. replace Rep3Share with SecretShare, anything that won't work?

 // TODO: curve init required? think not

  // (old) here we only need to initialize the curve params, not the field, because
  // the field is the same as the scalar field used by MPC and already
  // initialized!
  
    typedef Rep3Share<gfp_<0, 4>> ScalarShare;
    typedef Rep3Share<typename CommitmentScheme::CurvePoint> CurveShare;

  typename ScalarShare::mac_key_type input_mac_key;
  typename ScalarShare::read_or_generate_mac_key("", P, input_mac_key);
  scalar_opening_protocol = (typename ScalarShare::MAC_Check)(input_mac_key);

  // typename Rep3Share<typename CurvePoint>::mac_key_type input_mac_key2;
  typename CurveShare::mac_key_type input_mac_key2;
  // Rep3Share<typename CurvePoint>::read_or_generate_mac_key("", P,
  //                                                    input_mac_key2);
  typename CurveShare::read_or_generate_mac_key("", P,
                                                       input_mac_key2);
  // opening_protocol =
  //     (typename Rep3Share<typename CurvePoint>::MAC_Check)(input_mac_key2);
  opening_protocol =
      (typename CurveShare::MAC_Check)(input_mac_key2);

  mac_key = input_mac_key2;

  // P377Element::Scalar::init_field(gfp_<0, 4>::pr());

  //  bigint::init_thread();
  // sp.P.num_players();

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(P, false);
};
*/

// TODO: do we even need this?
/*
template <class CommitmentScheme>
ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::ConsistencyCheck(
    SubProcessor<Rep3Share<gfp_<0, 4>>> *sp)
    : scalar_input_protocol(sp, P), proc(sp) {
  std::cout << "specialized CC initializer\n";

    // TODO: could this be made Share-type agnostic? fully templated? i.e. replace Rep3Share with SecretShare, anything that won't work?

 // TODO: curve init required? think not

  // (old) here we only need to initialize the curve params, not the field, because
  // the field is the same as the scalar field used by MPC and already
  // initialized!
  

  typename ScalarShare::mac_key_type input_mac_key;
  (typename ScalarShare::read_or_generate_mac_key)("", P, input_mac_key);
  scalar_opening_protocol = (typename ScalarShare::MAC_Check)(input_mac_key);

  // typename Rep3Share<typename CurvePoint>::mac_key_type input_mac_key2;
  typename CurveShare::mac_key_type input_mac_key2;
  // Rep3Share<typename CurvePoint>::read_or_generate_mac_key("", P,
  //                                                    input_mac_key2);
  (typename CurveShare::read_or_generate_mac_key)("", P,
                                                       input_mac_key2);
  // opening_protocol =
  //     (typename Rep3Share<typename CurvePoint>::MAC_Check)(input_mac_key2);
  opening_protocol =
      (typename CurveShare::MAC_Check)(input_mac_key2);

  mac_key = input_mac_key2;

  // P377Element::Scalar::init_field(gfp_<0, 4>::pr());

  //  bigint::init_thread();
  // sp.P.num_players();

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(P, false);
}
*/



///////////////////////////////////////////////////////////////////////////////////////////
/// setup 
///////////////////////////////////////////////////////////////////////////////////////////

template <class T, class CommitmentScheme> 
void ConsistencyCheck<T, CommitmentScheme>::setup() {
  std::cout << "generic template setup: NOT IMPLEMENTED\n";
}

// TODO: specific implementations...
template <class CommitmentScheme> 
void ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::setup() {
    commitment_scheme.setup();
    setup_complete = true;
}

// TODO: specific implementations...
template <class CommitmentScheme> 
void ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::setup() {
    commitment_scheme.setup();

    /*
    opening_protocol.setup(*P);
    scalar_opening_protocol.setup(*P);
    */

    setup_complete = true;
}

///////////////////////////////////////////////////////////////////////////////////////////
/// commit_secret
///////////////////////////////////////////////////////////////////////////////////////////
template <class T, class CommitmentScheme>
void ConsistencyCheck<T, CommitmentScheme>::commit_secret(std::vector<T> &shares) {
    (void) shares;
    std::cout << "generic commit_secret(), NOT IMPLEMENTED\n";
}


template <class CommitmentScheme>
void ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<Rep3Share<gfp_<0, 4>>> &shares) {
    std::cout << "Rep3Share CC.commit_secret()\n";
    std::cout << "size: " << shares.size() << std::endl;


    // check if setup has been performed
    // TODO: access public params to check whether we have enough for our input?
    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return;
    }

    // vectors with "native" curve field (i.e. not MP-SPDZ wrapper)
    std::vector<typename CurvePoint::Field> coeffs1(shares.size()), coeffs2(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        // TODO: can this conversion be faster?
        Scalar ps1 = shares[i].get()[0];
        Scalar ps2 = shares[i].get()[1];

        convert_value(&coeffs1[i], &ps1);
        convert_value(&coeffs2[i], &ps2);
    }

    array<CurvePoint, 2> committed_shares = {
        commitment_scheme.commit(coeffs1), 
        commitment_scheme.commit(coeffs2)
    };

    CurveShare C_shared = CurveShare(committed_shares); // Rep3Share<CurvePoint>
    CurvePoint C = opening_protocol.open(C_shared, *P);
    opening_protocol.Check(*P);

    std::cout << "\nCommitment:\n";
    std::cout << C << std::endl << std::endl;
}


template <class CommitmentScheme>
void ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::commit_secret(std::vector<Share<gfp_<0, 4>>> &shares) {
    std::cout << "SPDZ CC.commit_secret()\n";

    ScalarShare s = shares[0];
    Scalar share = s.get_share();
    Scalar mac = s.get_mac();
    std::cout << "share: " << share << std::endl;
    std::cout << "mac: " << mac << std::endl;

    if (!setup_complete) {
        std::cout << "Setup not performed yet, must be done first!\n";
        return;
    }

    std::vector<typename CurvePoint::Field> inner_shares(shares.size()), macs(shares.size());

    for (unsigned long i = 0; i < shares.size(); i++) {
        // TODO: can this conversion be faster?
        Scalar share = shares[i].get_share();
        Scalar mac = shares[i].get_mac();

        convert_value(&inner_shares[i], &share);
        convert_value(&macs[i], &mac);
    }

    CurvePoint C_inner_share = commitment_scheme.commit(inner_shares);
    CurvePoint C_mac = commitment_scheme.commit(macs);

    CurveShare C_shared;
    C_shared.set_share(C_inner_share);
    C_shared.set_mac(C_mac);

    CurvePoint C = opening_protocol.open(C_shared, *P);
    // TODO: enable to check macs
    // opening_protocol.Check(*P);

    std::cout << "\nCommitment:\n";
    std::cout << C << std::endl << std::endl;
}

///////////////////////////////////////////////////////////////////////////////////////////
/// sign_commitment
///////////////////////////////////////////////////////////////////////////////////////////
template <class T, class CommitmentScheme>
void ConsistencyCheck<T, CommitmentScheme>::sign_commitment(std::string C) {
    (void) C;
    std::cout << "generic template CC.sign_commitment: NOT IMPLEMENTED\n";
}

// TODO: specific implementations...


///////////////////////////////////////////////////////////////////////////////////////////
/// check_batch
///////////////////////////////////////////////////////////////////////////////////////////
template <class T, class CommitmentScheme>
bool ConsistencyCheck<T, CommitmentScheme>::check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses) {
  (void)prover_nums;
  (void)input_sizes;
  (void)share_addresses;
  (void)clear_addresses;
  std::cout << "generic template CC.check_batch: NOT IMPLEMENTED\n";
  return false;
}

// NOTE: only the prover requires clear_input
template <class CommitmentScheme>
bool ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme>::check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses) {
    std::cout << "Rep3Share CC.check_batch\n";

    // TODO: each verifier groups together all proofs for which it is a verifier and not prover, and verifies them at once


    
/*   
 * Check:
 * 1. prover samples masking value omega <- F_p, and computes poly commitment to masking value 
 *  c_omega <- PC.Commit(omega)
 *  sends c_omega to all parties, and secret-shares omega itself
 * 2. parties jointly sample a random challenge beta (through MPC)
 * 3. parties invoke MPC to compute [rho] = [omega] + Sum_i{ [x_i] * beta^i } and subsequently open rho 
 *  basically, evaluate shared poly X at beta, and blind with omega. compute everything with shares
 * 4. prover generates a proof pi <- PC.Prove(c + c_omega, Poly[x] + Poly[omega], beta, rho), and sends pi to all verifiers
 * 5. verifiers run PC.Check with same inputs (except Poly of x and omega), to make sure evaluation proof is correct
 *  
 *  NOTE: only need PC.Prove and PC.Check/Verify for steps 4 and 5. for step 3, need to perform operations on secret shares (=> operations on field values)
 */

    // TODO: first test required functionalities!!!
    // - reading input commitment
    // - sending data 
    // - jointly sampling
    // - inputting values


    int my_num = P->my_num();

    /*
    int prover_num = 0;
    bool is_prover = (my_num == prover_num);

    CurvePoint C, c_omega;
    ScalarShare omega_shared;

    octetStream os, os_omega;

    Scalar omega;
    if (is_prover) {
        std::cout << "\n [I AM PROVER]\n";
        
        std::cout << "reading commitment from file...\n";
        bool res = read_single_hex_string(proc->Proc->commitment_input, os);
        if (!res) {
          std::cout << "\n >> Error when trying to read commitment from file! Aborting...\n\n";
          return false;
        }
        std::cout << "sending commitment to other parties...\n";
        P->send_all(os);

        std::cout << "prover: sampling masking value omega...\n";
        omega.randomize(secure_prng);

        std::cout << "omega: " << omega << std::endl;

        typename CurvePoint::Field omega_fr;
        convert_value(&omega_fr, &omega);

        std::vector<typename CurvePoint::Field> poly(1, omega_fr);
        c_omega = commitment_scheme.commit(poly);


        c_omega.pack(os_omega);
        P->send_all(os_omega);

    } else {
        std::cout << "\n [I AM VERIFIER]\n";
        P->receive_player(prover_num, os);
        P->receive_player(prover_num, os_omega);
        c_omega.unpack(os_omega);
    }
    // all:
    C.unpack(os);

    omega_shared = share_new_value(prover_num, omega, scalar_input_protocol, *P);

    if (is_prover) {
        std::cout << "\nread commitment from file:\n" << C << std::endl;
        std::cout << "commit(omega): " << c_omega << std::endl;
        std::cout << "share(omega): " << omega_shared << std::endl;
    } else {
        std::cout << "\nreceived commitment:\n" << C << std::endl;
        std::cout << "received commit(omega): " << c_omega << std::endl;
        std::cout << "share(omega): " << omega_shared << std::endl;
    }

    // TODO: check opening of omega, if correct
    std::cout << "\nopening omega to check correctness...\n";
    Scalar omega_opened = scalar_opening_protocol.open(omega_shared, *P);
    scalar_opening_protocol.Check(*P);

    std::cout << "omega: " << omega_opened << std::endl;

    if (is_prover) std::cout << "(prover) correct: " << (omega == omega_opened) << std::endl;


    Scalar r, r2;
    r.randomize(shared_prng);
    r2.randomize(shared_prng);
    std::cout << "\njointly sampling a random value...\n";
    std::cout << "r: " << r << std::endl << std::endl;
    std::cout << "r2: " << r2 << std::endl << std::endl;

    */

    /////////////////////////////////////////////////////////////////
    /// END OF TESTING
    /////////////////////////////////////////////////////////////////
        

    size_t n = prover_nums.size();
    // prepare verification inputs
    std::vector<ScalarShare> omega_shares(n);
    std::vector<CurvePoint> omega_commitments(n), commitments(n);
    std::vector<Scalar> rhos(n), prover_omegas(n);


    /*
    setup:

    compute all different values, store in vectors 
    in the end, in last for loop pass (where proofs are computed/distributed), assemble the verification lists


    */

    // TODO: should we keep it simple or try to be super efficient?
    // can minimize communication overhead by sending all data per party at once... but makes code more complex 
    // for now keep it simple
    // for prover-specific stuff, go through all inputs one by one, compute/send/receive on the spot



    // TODO: in the following loops, where can we aggregate e.g. communication/exchange data, like opening many values at once


    // 0. load and share all input commitments 
    // -> depends on who the prover is
    // TODO: send all at once?
    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == prover_nums[i];

        // TODO: is allocating a new octetStream for every iteration too inefficient?
        octetStream os;
        CurvePoint C;
        if (is_prover) {
            bool res = read_single_hex_string(proc->Proc->commitment_input, os);
            assert(res);
            P->send_all(os);
            C.unpack(os);
        } else {
            P->receive_player(prover_nums[i], os);
            C.unpack(os);
        }
        commitments[i] = C;
        std::cout << "\nLoaded input commitment:\n" << C << std::endl;
    }

    // 1. sample and share all masking values and masking commitments
    // -> depends on who the prover is

    // prepare input protocol (for secret-sharing values with other parties)
    scalar_input_protocol.reset_all(*P);

    // sample omegas, commit to omegas, send commitment and secret-share omega
    
    // TODO: can we do the sending/receiving of commitments more efficiently?
    // => can pack all commitments into one octetStream. but how to decode them so we still know which belongs to what?

    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == prover_nums[i];
        Scalar omega;
        CurvePoint c_omega;
        octetStream os;
        if (is_prover) {
            typename CurvePoint::Field omega_fr;

            omega.randomize(secure_prng);

            std::cout << "\nomega: " << omega << std::endl;
            prover_omegas[i] = omega;
            convert_value(&omega_fr, &omega);
            std::vector<typename CurvePoint::Field> poly(1, omega_fr);
            c_omega = commitment_scheme.commit(poly);
            c_omega.pack(os);
            P->send_all(os);

            scalar_input_protocol.add_mine(omega);
        } else {
            P->receive_player(prover_nums[i], os);
            c_omega.unpack(os);

            scalar_input_protocol.add_other(prover_nums[i]);
        }
        omega_commitments[i] = c_omega;

        std::cout << "\nC(omega): " << c_omega << std::endl;
    }

    scalar_input_protocol.exchange();
    
    for (size_t i=0;i<n;i++) {
        omega_shares[i] = scalar_input_protocol.finalize(prover_nums[i]);
    }

    // 2. sample random challenge beta
    // 3. compute and open all evaluations rho

    Scalar beta; // use a single beta, for batch verification
    beta.randomize(shared_prng);

    typename CurvePoint::Field beta_fr;
    convert_value(&beta_fr, &beta);

    auto share_memory = proc->get_S();
    std::vector<ScalarShare> rhos_shared(n);
    for (size_t i=0;i<n;i++) {
        ScalarShare rho_shared;
        rho_shared += omega_shares[i];

        int start_addr = share_addresses[i];

        // TODO: start with 1 or beta?
        Scalar current_beta = Scalar(1); // beta;
        for (int j = 0; j < input_sizes[i]; j++) { // can we parallelize this?
            rho_shared +=  share_memory[start_addr + j] * current_beta;
            current_beta = current_beta * beta;
        }

        // Scalar rho = scalar_opening_protocol.open(rho_shared);
        rhos_shared[i] = rho_shared;
    }
    // open all shares at once
    scalar_opening_protocol.POpen(rhos, rhos_shared, *P);
    // TODO: exchange all at once?
    // is this correct?
    scalar_opening_protocol.Check(*P);

    std::cout << "\nOpened rho: " << rhos[0] << std::endl;

    /*
 * 4. prover generates a proof pi <- PC.Prove(c + c_omega, Poly[x] + Poly[omega], beta, rho), and sends pi to all verifiers
 * 5. verifiers run PC.Check with same inputs (except Poly of x and omega), to make sure evaluation proof is correct
    */

    std::vector<Scalar> verify_rhos;
    std::vector<CurvePoint> verify_commitments, verify_proofs;

    // need to:
    // create a vector for each verification input with only the things i need to verify
    // at each step if i'm the prover, send my proof pi
    //
    // verify inputs: commitment; beta; rho; pi
    // z: evaluation point <-> beta
    // y: evaluation result <-> rho

    // 4. compute and share all proofs pi 
    // -> depends on who the prover is
    // also prepare the inputs for batch verification
    for (size_t i=0;i<n;i++) {
        // => we use poly. commit scheme here 
        CurvePoint c = commitments[i] + omega_commitments[i];
        octetStream os;
        CurvePoint pi;
        if (prover_nums[i] == my_num) {
            // compute and send proof
            std::vector<typename CurvePoint::Field> input_poly(input_sizes[i]);
            
            auto clear_memory = proc->get_C();
            int start_addr = clear_addresses[i];

            // TODO: correct?
            Scalar coeff0 = clear_memory[start_addr] + prover_omegas[i];
            std::cout << "\ncoeff0 (poly[0] + omega): " << coeff0 << std::endl;

            convert_value(&input_poly[0], &coeff0);
            std::cout << "updated input_poly[0]:\n";
            print_fr(&input_poly[0]);


            for (int j=1; j < input_sizes[i]; j++) {
                convert_value(&input_poly[j], &clear_memory[start_addr + j]);
            }
            typename CurvePoint::Field rho_fr;
            convert_value(&rho_fr, &rhos[i]);

            pi = commitment_scheme.prove(c.get_point(), input_poly, beta_fr, rho_fr);
            pi.pack(os);
            P->send_all(os);
        } else {
            // set up verification input
            verify_commitments.push_back(c);
            verify_rhos.push_back(rhos[i]);
            P->receive_player(prover_nums[i], os);
            pi.unpack(os);
            verify_proofs.push_back(pi);
        }
        std::cout << "\nProof pi: " << pi << std::endl;

        if (pi == CurvePoint()) {
            std::cout << "CommitmentScheme.prove failed, evaluation invalid.\n";
            return false;
        }

    }

    int n_verify = verify_commitments.size();
    if (n_verify == 0) return true;

    // 5. a) if we only have one commitment to verify, do it directly
    if (n_verify == 1) {
        std::cout << "\nperforming single verification...\n";
        typename CurvePoint::Field rho_fr;
        convert_value(&rho_fr, &verify_rhos[0]);
        return commitment_scheme.verify(verify_commitments[0].get_point(), beta_fr, rho_fr, verify_proofs[0].get_point());
    }
    // 5. b) otherwise perform batched verification
    std::cout << "\nperforming batch verification...\n";

    // TODO: might want to move this INSIDE of KZG commitment scheme 
    // since it is specific to that scheme

    Scalar current_gamma(1), gamma, rho_tilde(0);
    gamma.randomize(secure_prng);

    CurvePoint c_tilde(G1_IDENTITY), pi_tilde(G1_IDENTITY);
    for (size_t i = 0; i < verify_commitments.size(); i++) {
        c_tilde = c_tilde + current_gamma * verify_commitments[i]; 
        pi_tilde = pi_tilde + current_gamma * verify_proofs[i]; 
        rho_tilde = rho_tilde + current_gamma * verify_rhos[i];

        current_gamma = current_gamma * gamma;
    }

    typename CurvePoint::Field rho_tilde_fr;
    convert_value(&rho_tilde_fr, &rho_tilde);
    return commitment_scheme.verify(c_tilde.get_point(), beta_fr, rho_tilde_fr, pi_tilde.get_point());
}


/*
template <class CommitmentScheme>
bool ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses) {
    // TODO: remove those
  (void)prover_nums;
  (void)input_sizes;
  (void)share_addresses;
  (void)clear_addresses;
    std::cout << "SPDZ CC.check_batch!\n";
    return false;
}
*/

template <class CommitmentScheme>
bool ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme>::check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses) {
    std::cout << "SPDZ CC.check_batch\n";

    // TODO: each verifier groups together all proofs for which it is a verifier and not prover, and verifies them at once


    
/*   
 * Check:
 * 1. prover samples masking value omega <- F_p, and computes poly commitment to masking value 
 *  c_omega <- PC.Commit(omega)
 *  sends c_omega to all parties, and secret-shares omega itself
 * 2. parties jointly sample a random challenge beta (through MPC)
 * 3. parties invoke MPC to compute [rho] = [omega] + Sum_i{ [x_i] * beta^i } and subsequently open rho 
 *  basically, evaluate shared poly X at beta, and blind with omega. compute everything with shares
 * 4. prover generates a proof pi <- PC.Prove(c + c_omega, Poly[x] + Poly[omega], beta, rho), and sends pi to all verifiers
 * 5. verifiers run PC.Check with same inputs (except Poly of x and omega), to make sure evaluation proof is correct
 *  
 *  NOTE: only need PC.Prove and PC.Check/Verify for steps 4 and 5. for step 3, need to perform operations on secret shares (=> operations on field values)
 */

    // TODO: first test required functionalities!!!
    // - reading input commitment
    // - sending data 
    // - jointly sampling
    // - inputting values


    int my_num = P->my_num();

    /*
    int prover_num = 0;
    bool is_prover = (my_num == prover_num);

    CurvePoint C, c_omega;
    ScalarShare omega_shared;

    octetStream os, os_omega;

    Scalar omega;
    if (is_prover) {
        std::cout << "\n [I AM PROVER]\n";
        
        std::cout << "reading commitment from file...\n";
        bool res = read_single_hex_string(proc->Proc->commitment_input, os);
        if (!res) {
          std::cout << "\n >> Error when trying to read commitment from file! Aborting...\n\n";
          return false;
        }
        std::cout << "sending commitment to other parties...\n";
        P->send_all(os);

        std::cout << "prover: sampling masking value omega...\n";
        omega.randomize(secure_prng);

        std::cout << "omega: " << omega << std::endl;

        typename CurvePoint::Field omega_fr;
        convert_value(&omega_fr, &omega);

        std::vector<typename CurvePoint::Field> poly(1, omega_fr);
        c_omega = commitment_scheme.commit(poly);


        c_omega.pack(os_omega);
        P->send_all(os_omega);

    } else {
        std::cout << "\n [I AM VERIFIER]\n";
        P->receive_player(prover_num, os);
        P->receive_player(prover_num, os_omega);
        c_omega.unpack(os_omega);
    }
    // all:
    C.unpack(os);

    omega_shared = share_new_value(prover_num, omega, scalar_input_protocol, *P);

    if (is_prover) {
        std::cout << "\nread commitment from file:\n" << C << std::endl;
        std::cout << "commit(omega): " << c_omega << std::endl;
        std::cout << "share(omega): " << omega_shared << std::endl;
    } else {
        std::cout << "\nreceived commitment:\n" << C << std::endl;
        std::cout << "received commit(omega): " << c_omega << std::endl;
        std::cout << "share(omega): " << omega_shared << std::endl;
    }

    // TODO: check opening of omega, if correct
    std::cout << "\nopening omega to check correctness...\n";
    Scalar omega_opened = scalar_opening_protocol.open(omega_shared, *P);
    scalar_opening_protocol.Check(*P);

    std::cout << "omega: " << omega_opened << std::endl;

    if (is_prover) std::cout << "(prover) correct: " << (omega == omega_opened) << std::endl;


    Scalar r, r2;
    r.randomize(shared_prng);
    r2.randomize(shared_prng);
    std::cout << "\njointly sampling a random value...\n";
    std::cout << "r: " << r << std::endl << std::endl;
    std::cout << "r2: " << r2 << std::endl << std::endl;

    */

    /////////////////////////////////////////////////////////////////
    /// END OF TESTING
    /////////////////////////////////////////////////////////////////
        

    size_t n = prover_nums.size();
    // prepare verification inputs
    std::vector<ScalarShare> omega_shares(n);
    std::vector<CurvePoint> omega_commitments(n), commitments(n);
    std::vector<Scalar> rhos(n), prover_omegas(n);


    /*
    setup:

    compute all different values, store in vectors 
    in the end, in last for loop pass (where proofs are computed/distributed), assemble the verification lists


    */

    // TODO: should we keep it simple or try to be super efficient?
    // can minimize communication overhead by sending all data per party at once... but makes code more complex 
    // for now keep it simple
    // for prover-specific stuff, go through all inputs one by one, compute/send/receive on the spot



    // TODO: in the following loops, where can we aggregate e.g. communication/exchange data, like opening many values at once


    // 0. load and share all input commitments 
    // -> depends on who the prover is
    // TODO: send all at once?
    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == prover_nums[i];

        // TODO: is allocating a new octetStream for every iteration too inefficient?
        octetStream os;
        CurvePoint C;
        if (is_prover) {
            bool res = read_single_hex_string(proc->Proc->commitment_input, os);
            assert(res);
            P->send_all(os);
            C.unpack(os);
        } else {
            P->receive_player(prover_nums[i], os);
            C.unpack(os);
        }
        commitments[i] = C;
        std::cout << "\nLoaded input commitment:\n" << C << std::endl;
    }

    // 1. sample and share all masking values and masking commitments
    // -> depends on who the prover is

    // prepare input protocol (for secret-sharing values with other parties)
    scalar_input_protocol.reset_all(*P);

    // sample omegas, commit to omegas, send commitment and secret-share omega
    
    // TODO: can we do the sending/receiving of commitments more efficiently?
    // => can pack all commitments into one octetStream. but how to decode them so we still know which belongs to what?

    for (size_t i=0;i<n;i++) {
        bool is_prover = my_num == prover_nums[i];
        Scalar omega;
        CurvePoint c_omega;
        octetStream os;
        if (is_prover) {
            typename CurvePoint::Field omega_fr;

            omega.randomize(secure_prng);

            std::cout << "\nomega: " << omega << std::endl;
            prover_omegas[i] = omega;
            convert_value(&omega_fr, &omega);
            std::vector<typename CurvePoint::Field> poly(1, omega_fr);
            c_omega = commitment_scheme.commit(poly);
            c_omega.pack(os);
            P->send_all(os);

            scalar_input_protocol.add_mine(omega);
        } else {
            P->receive_player(prover_nums[i], os);
            c_omega.unpack(os);

            scalar_input_protocol.add_other(prover_nums[i]);
        }
        omega_commitments[i] = c_omega;

        std::cout << "\nC(omega): " << c_omega << std::endl;
    }

    scalar_input_protocol.exchange();
    
    for (size_t i=0;i<n;i++) {
        omega_shares[i] = scalar_input_protocol.finalize(prover_nums[i]);
    }

    // 2. sample random challenge beta
    // 3. compute and open all evaluations rho

    Scalar beta; // use a single beta, for batch verification
    beta.randomize(shared_prng);

    typename CurvePoint::Field beta_fr;
    convert_value(&beta_fr, &beta);

    auto share_memory = proc->get_S();
    std::vector<ScalarShare> rhos_shared(n);
    for (size_t i=0;i<n;i++) {
        ScalarShare rho_shared;
        rho_shared += omega_shares[i];

        int start_addr = share_addresses[i];

        // TODO: start with 1 or beta?
        Scalar current_beta = Scalar(1); // beta;
        for (int j = 0; j < input_sizes[i]; j++) { // can we parallelize this?
            rho_shared +=  share_memory[start_addr + j] * current_beta;
            current_beta = current_beta * beta;
        }

        // Scalar rho = scalar_opening_protocol.open(rho_shared);
        rhos_shared[i] = rho_shared;
    }
    // open all shares at once
    scalar_opening_protocol.POpen(rhos, rhos_shared, *P);
    // TODO: exchange all at once?
    // is this correct?

    // TODO: disable because of malicious mac check failure
    // scalar_opening_protocol.Check(*P);

    std::cout << "\nOpened rho: " << rhos[0] << std::endl;

    /*
 * 4. prover generates a proof pi <- PC.Prove(c + c_omega, Poly[x] + Poly[omega], beta, rho), and sends pi to all verifiers
 * 5. verifiers run PC.Check with same inputs (except Poly of x and omega), to make sure evaluation proof is correct
    */

    std::vector<Scalar> verify_rhos;
    std::vector<CurvePoint> verify_commitments, verify_proofs;

    // need to:
    // create a vector for each verification input with only the things i need to verify
    // at each step if i'm the prover, send my proof pi
    //
    // verify inputs: commitment; beta; rho; pi
    // z: evaluation point <-> beta
    // y: evaluation result <-> rho

    // 4. compute and share all proofs pi 
    // -> depends on who the prover is
    // also prepare the inputs for batch verification
    for (size_t i=0;i<n;i++) {
        // => we use poly. commit scheme here 
        CurvePoint c = commitments[i] + omega_commitments[i];
        octetStream os;
        CurvePoint pi;
        if (prover_nums[i] == my_num) {
            // compute and send proof
            std::vector<typename CurvePoint::Field> input_poly(input_sizes[i]);
            
            auto clear_memory = proc->get_C();
            int start_addr = clear_addresses[i];

            // TODO: correct?
            Scalar coeff0 = clear_memory[start_addr] + prover_omegas[i];
            std::cout << "\ncoeff0 (poly[0] + omega): " << coeff0 << std::endl;

            convert_value(&input_poly[0], &coeff0);
            std::cout << "updated input_poly[0]:\n";
            print_fr(&input_poly[0]);


            for (int j=1; j < input_sizes[i]; j++) {
                convert_value(&input_poly[j], &clear_memory[start_addr + j]);
            }
            typename CurvePoint::Field rho_fr;
            convert_value(&rho_fr, &rhos[i]);

            pi = commitment_scheme.prove(c.get_point(), input_poly, beta_fr, rho_fr);
            pi.pack(os);
            P->send_all(os);
        } else {
            // set up verification input
            verify_commitments.push_back(c);
            verify_rhos.push_back(rhos[i]);
            P->receive_player(prover_nums[i], os);
            pi.unpack(os);
            verify_proofs.push_back(pi);
        }
        std::cout << "\nProof pi: " << pi << std::endl;

        if (pi == CurvePoint()) {
            std::cout << "CommitmentScheme.prove failed, evaluation invalid.\n";
            return false;
        }

    }

    int n_verify = verify_commitments.size();
    if (n_verify == 0) return true;

    // 5. a) if we only have one commitment to verify, do it directly
    if (n_verify == 1) {
        std::cout << "\nperforming single verification...\n";
        typename CurvePoint::Field rho_fr;
        convert_value(&rho_fr, &verify_rhos[0]);
        return commitment_scheme.verify(verify_commitments[0].get_point(), beta_fr, rho_fr, verify_proofs[0].get_point());
    }
    // 5. b) otherwise perform batched verification
    std::cout << "\nperforming batch verification...\n";
    Scalar current_gamma(1), gamma, rho_tilde(0);
    gamma.randomize(secure_prng);

    CurvePoint c_tilde(G1_IDENTITY), pi_tilde(G1_IDENTITY);
    for (size_t i = 0; i < verify_commitments.size(); i++) {
        c_tilde = c_tilde + current_gamma * verify_commitments[i]; 
        pi_tilde = pi_tilde + current_gamma * verify_proofs[i]; 
        rho_tilde = rho_tilde + current_gamma * verify_rhos[i];

        current_gamma = current_gamma * gamma;
    }

    typename CurvePoint::Field rho_tilde_fr;
    convert_value(&rho_tilde_fr, &rho_tilde);
    return commitment_scheme.verify(c_tilde.get_point(), beta_fr, rho_tilde_fr, pi_tilde.get_point());
}



/// end

#endif
