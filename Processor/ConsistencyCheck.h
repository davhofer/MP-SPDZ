#ifndef CONSISTENCY_CHECK_H_
#define CONSISTENCY_CHECK_H_

// #include "Processor/Processor.h" // don't include, forward declare...
// #include "Protocols/Share.h"
#include "Protocols/Rep3Share.h"
#include "Protocols/Share.h"
// #include "Processor/Input.h" // TODO: will we need this?
#include "GC/SemiHonestRepPrep.h"
#include "Math/gfp.h"

#include "Processor/ConsistencyUtils.h"

// Forward declare SubProcessor
template<typename T>
class SubProcessor;

/*
template<typename U>
class HelperType {};

template<typename T>
struct ShareTypeExtractor {
    template<typename U>
    using type = HelperType<U>;
};

// Specialization for any template class with one parameter
template<template<typename> class Share, typename InnerType>
struct ShareTypeExtractor<Share<InnerType>> {
    template<typename U>
    using type = Share<U>;
};
*/

template<typename T>
struct ExtractShare;  // Primary template (not defined)

template<typename T>
struct ExtractShare {
    using type = T;  // Default: Keep T as is if no specialization applies
};

template<template<typename> class Outer, typename Inner>
struct ExtractShare<Outer<Inner>> {
    using type = Outer<Inner>;  // Extracts SecretShare<Inner>
};


template<typename T, typename NewInner>
struct ChangeInnerType;

// fallback
template<typename T, typename NewInner>
struct ChangeInnerType {
    using type = T;
};

template<template<typename> class Outer, typename OldInner, typename NewInner>
struct ChangeInnerType<Outer<OldInner>, NewInner> {
    using type = Outer<NewInner>;
};

// Example usage

template <class T, class CommitmentScheme> class ConsistencyCheck {
public:

    // define types
    // typedef typename CommitmentScheme::CurvePoint CurvePoint;
    // typedef typename CurvePoint::Scalar Scalar;
    
    // using ScalarShare = typename ChangeInnerType<T, Scalar>::type;
    // using CurveShare = typename ChangeInnerType<T, CurvePoint>::type;

    // typename CurveShare::Direct_MC opening_protocol;
    // typename ScalarShare::Direct_MC scalar_opening_protocol;
    // Input<ScalarShare> scalar_input_protocol;

    // CommitmentScheme commitment_scheme;

    // bool setup_complete = false;
    // typename CurveShare::mac_key_type mac_key;
    
    ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player);

    void setup();

    void commit_secret(std::vector<T> &shares);

    void sign_commitment(std::string C);

    bool check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses);
    /*
private:
  // SecretShare<CurvePoint>::mac_key_type::Scalar setup_opening_protocol(Player *player);
  // typename CurveShare::mac_key_type::Scalar setup_opening_protocol(Player &player);
  SubProcessor<T> *proc;
  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
  */
};


//////////////////////////////////////////////////////////////////////////////////////////////
/// Specialized
//////////////////////////////////////////////////////////////////////////////////////////////
///
/// TODO: fully copy of generic class, keep it simple
/// remove unnecessary parts from generic class

/*
template <class CommitmentScheme> 
class ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme> {
public:
    // TODO: maybe add Input<Rep3Share<gfp_<0, 4>>> scalar_input_protocol here??;
    // ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp);
    void convert_shares(std::vector<Rep3Share<gfp_<0, 4>>> &shares,
                  std::vector<Rep3Share<typename CommitmentScheme::CurvePoint::Scalar>> &converted);
};
*/

template <class CommitmentScheme> 
class ConsistencyCheck<Rep3Share<gfp_<0, 4>>, CommitmentScheme> {
public:
    // define types
    
    using T = Rep3Share<gfp_<0, 4>>;
    typedef typename CommitmentScheme::CurvePoint CurvePoint;
    typedef typename CurvePoint::Scalar Scalar;
    
    using ScalarShare = Rep3Share<Scalar>; 
    using CurveShare = Rep3Share<CurvePoint>; 

    // SecretShare<typename CurvePoint>::Direct_MC opening_protocol;
    typename CurveShare::Direct_MC opening_protocol;
    // SecretShare<typename Scalar>::Direct_MC scalar_opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    Input<ScalarShare> scalar_input_protocol;
    // TODO: maybe add Input<Rep3Share<gfp_<0, 4>>> scalar_input_protocol here??;
    // ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp);

    CommitmentScheme commitment_scheme;

    // remove because we don't know yet how to create the scalar input protocol
    // nicely Input<SecretShare<typename PC::G1::Scalar>> scalar_input_protocol;
    // TODO: do we need this???
    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player);

    void setup();

    void commit_secret(std::vector<T> &shares);

    // TODO: signing
    void sign_commitment(std::string C);

    bool check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses);

private:
  // SecretShare<CurvePoint>::mac_key_type::Scalar setup_opening_protocol(Player *player);
  // typename CurveShare::mac_key_type::Scalar setup_opening_protocol(Player &player);
  SubProcessor<T> *proc;
  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
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

    // SecretShare<typename CurvePoint>::Direct_MC opening_protocol;
    typename CurveShare::Direct_MC opening_protocol;
    // SecretShare<typename Scalar>::Direct_MC scalar_opening_protocol;
    typename ScalarShare::Direct_MC scalar_opening_protocol;
    Input<ScalarShare> scalar_input_protocol;
    // TODO: maybe add Input<Rep3Share<gfp_<0, 4>>> scalar_input_protocol here??;
    // ConsistencyCheck(SubProcessor<Rep3Share<gfp_<0, 4>>> *sp);

    CommitmentScheme commitment_scheme;

    // remove because we don't know yet how to create the scalar input protocol
    // nicely Input<SecretShare<typename PC::G1::Scalar>> scalar_input_protocol;
    // TODO: do we need this???
    bool setup_complete = false;
    typename CurveShare::mac_key_type mac_key;

    ConsistencyCheck();

    ConsistencyCheck(SubProcessor<T> *sp, Player *player);

    void setup();

    void commit_secret(std::vector<T> &shares);

    // TODO: signing
    void sign_commitment(std::string C);

    bool check_batch(std::vector<int> &prover_nums, std::vector<int> &input_sizes, std::vector<int> &share_addresses, std::vector<int> &clear_addresses);

private:
  // SecretShare<CurvePoint>::mac_key_type::Scalar setup_opening_protocol(Player *player);
  // typename CurveShare::mac_key_type::Scalar setup_opening_protocol(Player &player);
  SubProcessor<T> *proc;
  Player *P;
  PRNG shared_prng;
  PRNG secure_prng;
};

#include "Processor/ConsistencyCheck.cpp"

#endif
