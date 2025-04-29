#ifndef CONSISTENCY_CHECK_H_
#define CONSISTENCY_CHECK_H_

#include "Protocols/ShamirShare.h"
#include "Protocols/Rep3Share.h"
#include "Protocols/Share.h"

#include "GC/SemiHonestRepPrep.h"

#include "Processor/P381Element.h"

#include "Processor/CommitmentScheme.h"

// Forward declare SubProcessor
template<typename T>
class SubProcessor;


template<class T, class CurveShare, class ScalarShare>
bool check_commitment(
    const std::vector<int> &args,
    MemoryPart<T> &memory,
    std::vector<std::vector<gfp_<0, 4>>> &clear_inputs,
    KZGCommitmentScheme &commitment_scheme,
    ConsistencyCheck<T, KZGCommitmentScheme> *cc
);

template<class T, class CurveShare, class ScalarShare>
bool check_commitment(
    const std::vector<int> &args,
    MemoryPart<T> &memory,
    std::vector<std::vector<gfp_<0, 4>>> &clear_inputs,
    PedVecCommitmentScheme &commitment_scheme,
    ConsistencyCheck<T, PedVecCommitmentScheme> *cc
);

// Templating magic to extract inenr type (not used currently)
template<typename T>
struct ExtractShare;

template<typename T>
struct ExtractShare {
    using type = T;  
};

template<template<typename> class Outer, typename Inner>
struct ExtractShare<Outer<Inner>> {
    using type = Outer<Inner>;  // Extracts SecretShare<Inner>
};

template<typename T, typename NewInner>
struct ChangeInnerType;

template<typename T, typename NewInner>
struct ChangeInnerType {
    using type = T;
};

template<template<typename> class Outer, typename OldInner, typename NewInner>
struct ChangeInnerType<Outer<OldInner>, NewInner> {
    using type = Outer<NewInner>;
};
// Example usage
// using ScalarShare = typename ChangeInnerType<T, Scalar>::type;


template <class T, class CommitmentScheme> class ConsistencyCheck {
public:

    bool setup_complete = false;
    
    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<typename T::clear> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(typename CommitmentScheme::CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

};


//////////////////////////////////////////////////////////////////////////////////////////////
/// Specialized
//////////////////////////////////////////////////////////////////////////////////////////////


template <class CommitmentScheme> 
class ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    
    using T = Rep3Share<gfp_<0, 4>>;
    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = Rep3Share<Scalar>; 
    using CurveShare = Rep3Share<CurvePoint>; 
    using PkShare = Rep3Share<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = Rep3Share<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 


    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};


template <class CommitmentScheme> 
class ConsistencyCheck<Share<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    using T = Share<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = Share<Scalar>; 
    using CurveShare = Share<CurvePoint>; 
    using PkShare = Share<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = Share<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};


// conditional compilation
#ifdef PROTOCOLS_SPDZWISESHARE_H_
#ifdef PROTOCOLS_MALICIOUSREP3SHARE_H_
// sy-rep-field
// SpdzWiseRepFieldShare
template <class CommitmentScheme> 
class ConsistencyCheck<SpdzWiseRepFieldShare<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    
    using T = SpdzWiseRepFieldShare<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = SpdzWiseRepFieldShare<Scalar>; 
    using CurveShare = SpdzWiseRepFieldShare<CurvePoint>; 
    using PkShare = SpdzWiseRepFieldShare<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = SpdzWiseRepFieldShare<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};
#endif
#endif

#ifdef PROTOCOLS_TEMISHARE_H_
// TemiShare 
template <class CommitmentScheme> 
class ConsistencyCheck<TemiShare<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    using T = TemiShare<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = TemiShare<Scalar>; 
    using CurveShare = TemiShare<CurvePoint>; 
    using PkShare = TemiShare<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = TemiShare<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};
#endif

#ifdef PROTOCOLS_ATLASSHARE_H_
// AtlasShare 
template <class CommitmentScheme> 
class ConsistencyCheck<AtlasShare<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    using T = AtlasShare<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = AtlasShare<Scalar>; 
    using CurveShare = AtlasShare<CurvePoint>; 
    using PkShare = AtlasShare<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = AtlasShare<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};
#endif

// conditional compilation
#ifdef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
// mal-shamir
// MaliciousShamirShare
template <class CommitmentScheme> 
class ConsistencyCheck<MaliciousShamirShare<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    using T = MaliciousShamirShare<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = MaliciousShamirShare<Scalar>; 
    using CurveShare = MaliciousShamirShare<CurvePoint>; 
    using PkShare = MaliciousShamirShare<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = MaliciousShamirShare<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ShamirShare<Scalar>::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};


template <class CommitmentScheme> 
class ConsistencyCheck<ShamirShare<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    using T = ShamirShare<gfp_<0, 4>>;

    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = ShamirShare<Scalar>; 
    using CurveShare = ShamirShare<CurvePoint>; 
    using PkShare = ShamirShare<P381Element>; 

    typename CurveShare::Direct_MC opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    typename PkShare::Direct_MC sig_pk_protocol;

    using SigShare = ShamirShare<P381ElementG2>; 
    typename SigShare::Direct_MC sig_protocol;

    typename ScalarShare::Protocol random_protocol;

    Input<ScalarShare> scalar_input_protocol;

    CommitmentScheme commitment_scheme;

    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    StackedVector<T> *S_ptr;
    StackedVector<gfp_<0, 4>> *C_ptr;
    ifstream *commitment_input;

    std::ifstream personal_input; 

    ConsistencyCheck();
    ~ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player, StackedVector<T> *processor_S, StackedVector<gfp_<0, 4>> *processor_C, ifstream *processor_commitment_input, typename T::mac_key_type::Scalar alphai);

    void setup(size_t d);

    typename CommitmentScheme::CurvePoint commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(const std::vector<int> &args, MemoryPart<T> &memory);

    void setup_signing_keys();
    P381ElementG2 dist_sign(CurvePoint &p);
    bool verify_signature(P381ElementG2 &signature);

  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
    ScalarShare sig_sk;
    P381Element sig_pk;
};

#endif

#include "Processor/ConsistencyCheck.hpp"

#endif
