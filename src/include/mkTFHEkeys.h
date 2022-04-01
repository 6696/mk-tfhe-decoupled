#ifndef MKTFHEKEYS_H
#define MKTFHEKEYS_H

#include "lwekey.h"
#include "tfhe_core.h"
#include <iostream>
#include <vector>
#include "mkTFHEsamples.h"
#include "lwekeyswitch.h"


struct MKLweKey {
   const LweParams* LWEparams;
   const MKTFHEParams* MKparams;

   LweKey* key; // LWE secret keys for all the parties

    void serialize(std::string path) {
        std::fstream os = std::fstream(path, std::ios::out | std::ios::binary);
        // LWEparams
        os.write((char *) LWEparams, sizeof(LweParams));

        // MKparams
        os.write((char *) &MKparams->n,	sizeof( int32_t));// LWE modulus
        os.write((char *) &MKparams->n_extract,	sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        os.write((char *) &MKparams->hLWE,			sizeof( int32_t));// HW secret key LWE
        os.write((char *) &MKparams->stdevLWE,		sizeof( double ));// LWE ciphertexts standard deviation
        os.write((char *) &MKparams->Bksbit,		sizeof( int32_t));// Base bit key switching
        os.write((char *) &MKparams->dks,			sizeof( int32_t));// dimension key switching
        os.write((char *) &MKparams->stdevKS,		sizeof( double ));// KS key standard deviation
        os.write((char *) &MKparams->N,			sizeof( int32_t));// RLWE,RGSW modulus
        os.write((char *) &MKparams->hRLWE,		sizeof( int32_t));// HW secret key RLWE,RGSW
        os.write((char *) &MKparams->stdevRLWEkey,	sizeof( double ));// RLWE key standard deviation
        os.write((char *) &MKparams->stdevRLWE,	sizeof( double ));	// RLWE ciphertexts standard deviation
        os.write((char *) &MKparams->stdevRGSW,	sizeof( double ));	// RGSW ciphertexts standard deviation
        os.write((char *) &MKparams->Bgbit,		sizeof( int32_t));// Base bit gadget
        os.write((char *) &MKparams->dg,			sizeof( int32_t));// dimension gadget
        os.write((char *) &MKparams->stdevBK,		sizeof( double ));// BK standard deviation
        os.write((char *) &MKparams->parties,		sizeof( int32_t));// number of parties
        os.write((char *) &MKparams->maskMod,		sizeof(uint32_t));// Bg - 1
        os.write((char *) &MKparams->halfBg,		sizeof( int32_t));// Bg/2
        os.write((char *) MKparams->g,		sizeof( Torus32));// Bg/2
        os.write((char *) &MKparams->offset,		sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        //key
//        os.write((char *) key->params, sizeof(LweParams));
        for (int i = 0; i < MKparams->parties; i++){
//            os.write((char *) LWEparams, sizeof(LweParams));
            os.write((char *) key[i].params, sizeof(LweParams));
            os.write((char *) key[i].key, sizeof(int32_t) * key[i].params->n);
        }
    }

    void deserialize(std::string path) {
        std::fstream is = std::fstream(path, std::ios::in | std::ios::binary);

        // LWEparams
        is.read((char *) LWEparams, sizeof(LweParams));

        // MKparams
        is.read((char *) &MKparams->n,	sizeof( int32_t));// LWE modulus
        is.read((char *) &MKparams->n_extract,	sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        is.read((char *) &MKparams->hLWE,			sizeof( int32_t));// HW secret key LWE
        is.read((char *) &MKparams->stdevLWE,		sizeof( double ));// LWE ciphertexts standard deviation
        is.read((char *) &MKparams->Bksbit,		sizeof( int32_t));// Base bit key switching
        is.read((char *) &MKparams->dks,			sizeof( int32_t));// dimension key switching
        is.read((char *) &MKparams->stdevKS,		sizeof( double ));// KS key standard deviation
        is.read((char *) &MKparams->N,			sizeof( int32_t));// RLWE,RGSW modulus
        is.read((char *) &MKparams->hRLWE,		sizeof( int32_t));// HW secret key RLWE,RGSW
        is.read((char *) &MKparams->stdevRLWEkey,	sizeof( double ));// RLWE key standard deviation
        is.read((char *) &MKparams->stdevRLWE,	sizeof( double ));	// RLWE ciphertexts standard deviation
        is.read((char *) &MKparams->stdevRGSW,	sizeof( double ));	// RGSW ciphertexts standard deviation
        is.read((char *) &MKparams->Bgbit,		sizeof( int32_t));// Base bit gadget
        is.read((char *) &MKparams->dg,			sizeof( int32_t));// dimension gadget
        is.read((char *) &MKparams->stdevBK,		sizeof( double ));// BK standard deviation
        is.read((char *) &MKparams->parties,		sizeof( int32_t));// number of parties
        is.read((char *) &MKparams->maskMod,		sizeof(uint32_t));// Bg - 1
        is.read((char *) &MKparams->halfBg,		sizeof( int32_t));// Bg/2
        is.read((char *) MKparams->g,		sizeof( Torus32));// Bg/2
        is.read((char *) &MKparams->offset,		sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        for (int i = 0; i < MKparams->parties; i++){
//            os.write((char *) LWEparams, sizeof(LweParams));
            is.read((char *) key[i].params, sizeof(LweParams));
            is.read((char *) key[i].key, sizeof(int32_t) * key[i].params->n);
        }
    }

#ifdef __cplusplus   
   MKLweKey(const LweParams* LWEparams, const MKTFHEParams* MKparams);
   ~MKLweKey();
   MKLweKey(const MKLweKey&) = delete; //forbidden 
   MKLweKey* operator=(const MKLweKey&) = delete; //forbidden
#endif
};



// allocate memory space 
EXPORT MKLweKey* alloc_MKLweKey();
EXPORT MKLweKey* alloc_MKLweKey_array(int32_t nbelts);
// free memory space 
EXPORT void free_MKLweKey(MKLweKey* ptr);
EXPORT void free_MKLweKey_array(int32_t nbelts, MKLweKey* ptr);
// initialize the structure
EXPORT void init_MKLweKey(MKLweKey* obj, const LweParams* LWEparams, const MKTFHEParams* MKparams);
EXPORT void init_MKLweKey_array(int32_t nbelts, MKLweKey* obj, const LweParams* LWEparams, 
        const MKTFHEParams* MKparams);
// destroys the structure
EXPORT void destroy_MKLweKey(MKLweKey* obj);
EXPORT void destroy_MKLweKey_array(int32_t nbelts, MKLweKey* obj);
// new = alloc + init
EXPORT MKLweKey* new_MKLweKey(const LweParams* LWEparams, const MKTFHEParams* MKparams);
EXPORT MKLweKey* new_MKLweKey_array(int32_t nbelts, const LweParams* LWEparams, const MKTFHEParams* MKparams);
// delete = destroy + free
EXPORT void delete_MKLweKey(MKLweKey* obj);
EXPORT void delete_MKLweKey_array(int32_t nbelts, MKLweKey* obj);



















struct MKRLweKey {
    const TLweParams* RLWEparams;
    const MKTFHEParams* MKparams;

    TLweKey* key; // RLWE secret keys for all the parties
    TorusPolynomial* Pkey; // RLWE public keys for all the parties


    void serialize(std::string path) {
        std::fstream os = std::fstream(path, std::ios::out | std::ios::binary);
        // LWEparams
        os.write((char *) RLWEparams, sizeof(TLweParams));

        // MKparams
        os.write((char *) &MKparams->n,	sizeof( int32_t));// LWE modulus
        os.write((char *) &MKparams->n_extract,	sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        os.write((char *) &MKparams->hLWE,			sizeof( int32_t));// HW secret key LWE
        os.write((char *) &MKparams->stdevLWE,		sizeof( double ));// LWE ciphertexts standard deviation
        os.write((char *) &MKparams->Bksbit,		sizeof( int32_t));// Base bit key switching
        os.write((char *) &MKparams->dks,			sizeof( int32_t));// dimension key switching
        os.write((char *) &MKparams->stdevKS,		sizeof( double ));// KS key standard deviation
        os.write((char *) &MKparams->N,			sizeof( int32_t));// RLWE,RGSW modulus
        os.write((char *) &MKparams->hRLWE,		sizeof( int32_t));// HW secret key RLWE,RGSW
        os.write((char *) &MKparams->stdevRLWEkey,	sizeof( double ));// RLWE key standard deviation
        os.write((char *) &MKparams->stdevRLWE,	sizeof( double ));	// RLWE ciphertexts standard deviation
        os.write((char *) &MKparams->stdevRGSW,	sizeof( double ));	// RGSW ciphertexts standard deviation
        os.write((char *) &MKparams->Bgbit,		sizeof( int32_t));// Base bit gadget
        os.write((char *) &MKparams->dg,			sizeof( int32_t));// dimension gadget
        os.write((char *) &MKparams->stdevBK,		sizeof( double ));// BK standard deviation
        os.write((char *) &MKparams->parties,		sizeof( int32_t));// number of parties
        os.write((char *) &MKparams->maskMod,		sizeof(uint32_t));// Bg - 1
        os.write((char *) &MKparams->halfBg,		sizeof( int32_t));// Bg/2
        os.write((char *) MKparams->g,		sizeof( Torus32));// Bg/2
        os.write((char *) &MKparams->offset,		sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        //only public keys
        const int32_t dg = MKparams->dg;
        for (int i = 0; i <= MKparams->parties; ++i)
        {
            for (int j = 0; j < dg; ++j)
            {
                os.write((char *) &Pkey[i*dg + j].N, sizeof(int32_t));
                const int32_t N = Pkey[i*dg + j].N;
                Torus32 *__restrict r = Pkey[i*dg + j].coefsT;
                for (int32_t l = 0; i < N; ++i){
                    os.write((char *) &r[l], sizeof(Torus32));
                }
            }
        }
    }

    void deserialize(std::string path) {
        std::fstream is = std::fstream(path, std::ios::in | std::ios::binary);

        // LWEparams
        is.read((char *) RLWEparams, sizeof(TLweParams));

        // MKparams
        is.read((char *) &MKparams->n,	sizeof( int32_t));// LWE modulus
        is.read((char *) &MKparams->n_extract,	sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        is.read((char *) &MKparams->hLWE,			sizeof( int32_t));// HW secret key LWE
        is.read((char *) &MKparams->stdevLWE,		sizeof( double ));// LWE ciphertexts standard deviation
        is.read((char *) &MKparams->Bksbit,		sizeof( int32_t));// Base bit key switching
        is.read((char *) &MKparams->dks,			sizeof( int32_t));// dimension key switching
        is.read((char *) &MKparams->stdevKS,		sizeof( double ));// KS key standard deviation
        is.read((char *) &MKparams->N,			sizeof( int32_t));// RLWE,RGSW modulus
        is.read((char *) &MKparams->hRLWE,		sizeof( int32_t));// HW secret key RLWE,RGSW
        is.read((char *) &MKparams->stdevRLWEkey,	sizeof( double ));// RLWE key standard deviation
        is.read((char *) &MKparams->stdevRLWE,	sizeof( double ));	// RLWE ciphertexts standard deviation
        is.read((char *) &MKparams->stdevRGSW,	sizeof( double ));	// RGSW ciphertexts standard deviation
        is.read((char *) &MKparams->Bgbit,		sizeof( int32_t));// Base bit gadget
        is.read((char *) &MKparams->dg,			sizeof( int32_t));// dimension gadget
        is.read((char *) &MKparams->stdevBK,		sizeof( double ));// BK standard deviation
        is.read((char *) &MKparams->parties,		sizeof( int32_t));// number of parties
        is.read((char *) &MKparams->maskMod,		sizeof(uint32_t));// Bg - 1
        is.read((char *) &MKparams->halfBg,		sizeof( int32_t));// Bg/2
        is.read((char *) MKparams->g,		sizeof( Torus32));// Bg/2
        is.read((char *) &MKparams->offset,		sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        //only public keys
        const int32_t dg = MKparams->dg;
        for (int i = 0; i <= MKparams->parties; ++i)
        {
            for (int j = 0; j < dg; ++j)
            {
                is.read((char *) &Pkey[i*dg + j].N, sizeof(int32_t));
                const int32_t N = Pkey[i*dg + j].N;
                Torus32 *__restrict r = Pkey[i*dg + j].coefsT;
                for (int32_t l = 0; l < N; ++l){
                    is.read((char *) &r[l], sizeof(Torus32));
                }
            }
        }
    }

#ifdef __cplusplus
    MKRLweKey(const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
    ~MKRLweKey();
    MKRLweKey(const MKRLweKey &) = delete;
    MKRLweKey* operator=(const MKRLweKey &) = delete;
#endif
};



// allocate memory space 
EXPORT MKRLweKey* alloc_MKRLweKey();
EXPORT MKRLweKey* alloc_MKRLweKey_array(int32_t nbelts);
// free memory space 
EXPORT void free_MKRLweKey(MKRLweKey* ptr);
EXPORT void free_MKRLweKey_array(int32_t nbelts, MKRLweKey* ptr);
// initialize the structure
EXPORT void init_MKRLweKey(MKRLweKey* obj, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT void init_MKRLweKey_array(int32_t nbelts, MKRLweKey* obj, const TLweParams* RLWEparams, 
        const MKTFHEParams* MKparams);
// destroys the structure
EXPORT void destroy_MKRLweKey(MKRLweKey* obj);
EXPORT void destroy_MKRLweKey_array(int32_t nbelts, MKRLweKey* obj);
// new = alloc + init
EXPORT MKRLweKey* new_MKRLweKey(const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT MKRLweKey* new_MKRLweKey_array(int32_t nbelts, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
// delete = destroy + free
EXPORT void delete_MKRLweKey(MKRLweKey* obj);
EXPORT void delete_MKRLweKey_array(int32_t nbelts, MKRLweKey* obj);


























/* *******************************************************
*************** Key Switching Key ************************
******************************************************* */

struct MKLweKeySwitchKey {
    int32_t n_in;                 // length input key
    int32_t n_out;                // length output key
    int32_t parties;              // number of parties
    int32_t Bksbit;               // KS basebit
    int32_t Bks;                  // KS base
    int32_t dks;                  // KS lenght
    const MKTFHEParams* params;
    MKLweSample* ks0_raw;         // vector of size parties*n_in*dks*Bks
    MKLweSample** ks1_raw;        
    MKLweSample*** ks2_raw;       
    MKLweSample**** ks;           

#ifdef __cplusplus
    MKLweKeySwitchKey(int32_t n_in, const MKTFHEParams* params, MKLweSample* ks0_raw);
    ~MKLweKeySwitchKey();
    MKLweKeySwitchKey(const MKLweKeySwitchKey&) = delete;
    void operator=(const MKLweKeySwitchKey&) = delete;
#endif
};


// alloc 
EXPORT MKLweKeySwitchKey* alloc_MKLweKeySwitchKey();
EXPORT MKLweKeySwitchKey* alloc_MKLweKeySwitchKey_array(int32_t nbelts);
// free memory space 
EXPORT void free_MKLweKeySwitchKey(MKLweKeySwitchKey* ptr);
EXPORT void free_MKLweKeySwitchKey_array(int32_t nbelts, MKLweKeySwitchKey* ptr);
// initialize the structure
EXPORT void init_MKLweKeySwitchKey(MKLweKeySwitchKey* obj, int32_t n_in, const LweParams* LWEparams, 
        const MKTFHEParams* params);
EXPORT void init_MKLweKeySwitchKey_array(int32_t nbelts, MKLweKeySwitchKey* obj, int32_t n_in, 
        const LweParams* LWEparams, const MKTFHEParams* params);
// destroy 
EXPORT void destroy_MKLweKeySwitchKey(MKLweKeySwitchKey* obj);
EXPORT void destroy_MKLweKeySwitchKey_array(int32_t nbelts, MKLweKeySwitchKey* obj);
// new = alloc + init 
EXPORT MKLweKeySwitchKey* new_MKLweKeySwitchKey(int32_t n_in, const LweParams* LWEparams, const MKTFHEParams* params);
EXPORT MKLweKeySwitchKey* new_MKLweKeySwitchKey_array(int32_t nbelts, int32_t n_in, const LweParams* LWEparams, 
        const MKTFHEParams* params);
// delete = destroy + free 
EXPORT void delete_MKLweKeySwitchKey(MKLweKeySwitchKey* obj);
EXPORT void delete_MKLweKeySwitchKey_array(int32_t nbelts, MKLweKeySwitchKey* obj);
















/* *******************************************************
*************** Bootstrapping Key v2 *********************
******************************************************* */


struct MKLweBootstrappingKey_v2{
    const MKTFHEParams* MKparams;
    MKTGswUESample_v2* bk;
    LweKeySwitchKey* ks; //MKLweKeySwitchKey* ks;

    void serialize(std::string path) {
        std::fstream os = std::fstream(path, std::ios::out | std::ios::binary);
        // MKparams
        os.write((char *) &MKparams->n,	sizeof( int32_t));// LWE modulus
        os.write((char *) &MKparams->n_extract,	sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        os.write((char *) &MKparams->hLWE,			sizeof( int32_t));// HW secret key LWE
        os.write((char *) &MKparams->stdevLWE,		sizeof( double ));// LWE ciphertexts standard deviation
        os.write((char *) &MKparams->Bksbit,		sizeof( int32_t));// Base bit key switching
        os.write((char *) &MKparams->dks,			sizeof( int32_t));// dimension key switching
        os.write((char *) &MKparams->stdevKS,		sizeof( double ));// KS key standard deviation
        os.write((char *) &MKparams->N,			sizeof( int32_t));// RLWE,RGSW modulus
        os.write((char *) &MKparams->hRLWE,		sizeof( int32_t));// HW secret key RLWE,RGSW
        os.write((char *) &MKparams->stdevRLWEkey,	sizeof( double ));// RLWE key standard deviation
        os.write((char *) &MKparams->stdevRLWE,	sizeof( double ));	// RLWE ciphertexts standard deviation
        os.write((char *) &MKparams->stdevRGSW,	sizeof( double ));	// RGSW ciphertexts standard deviation
        os.write((char *) &MKparams->Bgbit,		sizeof( int32_t));// Base bit gadget
        os.write((char *) &MKparams->dg,			sizeof( int32_t));// dimension gadget
        os.write((char *) &MKparams->stdevBK,		sizeof( double ));// BK standard deviation
        os.write((char *) &MKparams->parties,		sizeof( int32_t));// number of parties
        os.write((char *) &MKparams->maskMod,		sizeof(uint32_t));// Bg - 1
        os.write((char *) &MKparams->halfBg,		sizeof( int32_t));// Bg/2
        os.write((char *) MKparams->g,		sizeof( Torus32));// Bg/2
        os.write((char *) &MKparams->offset,		sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        //bootstrapping key
        const int32_t n = MKparams->n;
        const int32_t parties = MKparams->parties;
        for (int i = 0; i < parties; ++i)
        {
            for (int j = 0; j < n; ++j)
            {
                MKTGswUESample_v2* bk_i = &bk[i*n+j];

                os.write((char *) &bk_i->party,		sizeof( int32_t));
                os.write((char *) &bk_i->current_variance,		sizeof( double));
                os.write((char *) &bk_i->dg,		sizeof( int32_t));
                os.write((char *) &bk_i->N,		sizeof( int32_t));

                for (int l = 0; l < 3 * bk_i->dg; l++) {
                    os.write((char *) &bk_i->d[l], sizeof(TorusPolynomial));
                }
//                f0 = d + dg;
//                f1 = d + 2*dg;
            }
        }

        //ksk
        for (int p = 0; p < parties; ++p)
        {
            LweKeySwitchKey* ks_i = &ks[p];
            const int32_t t = ks_i->t;
            const int32_t base = ks_i->base;

            os.write((char *) &ks_i->n,		sizeof( int32_t));
            os.write((char *) &ks_i->t,        sizeof( int32_t));
            os.write((char *) &ks_i->basebit,  sizeof( int32_t));
            os.write((char *) &ks_i->base,		sizeof( int32_t));


            for (int32_t i = 0; i < n; ++i) {
                for (int32_t j = 0; j < t; ++j) {
                    for (int32_t h = 0; h < base; ++h) {
                        os.write((char *) &ks_i->ks[i][j][h].current_variance,		sizeof( double));
                        os.write((char *) &ks_i->ks[i][j][h].b,		sizeof( Torus32));

                        for (int32_t z = 0; z < n; ++z)
                        {
                            os.write((char *) &ks_i->ks[i][j][h].a[z],		sizeof( Torus32));
                        }
                    }
                }
            }

        }
    }

    void deserialize(std::string path) {
        std::fstream is = std::fstream(path, std::ios::in | std::ios::binary);
        // MKparams
        is.read((char *) &MKparams->n, sizeof( int32_t));// LWE modulus
        is.read((char *) &MKparams->n_extract, sizeof( int32_t));// LWE extract modulus (used in bootstrapping)
        is.read((char *) &MKparams->hLWE, sizeof( int32_t));// HW secret key LWE
        is.read((char *) &MKparams->stdevLWE, sizeof( double ));// LWE ciphertexts standard deviation
        is.read((char *) &MKparams->Bksbit, sizeof( int32_t));// Base bit key switching
        is.read((char *) &MKparams->dks, sizeof( int32_t));// dimension key switching
        is.read((char *) &MKparams->stdevKS, sizeof( double ));// KS key standard deviation
        is.read((char *) &MKparams->N, sizeof( int32_t));// RLWE,RGSW modulus
        is.read((char *) &MKparams->hRLWE, sizeof( int32_t));// HW secret key RLWE,RGSW
        is.read((char *) &MKparams->stdevRLWEkey, sizeof( double ));// RLWE key standard deviation
        is.read((char *) &MKparams->stdevRLWE, sizeof( double ));	// RLWE ciphertexts standard deviation
        is.read((char *) &MKparams->stdevRGSW, sizeof( double ));	// RGSW ciphertexts standard deviation
        is.read((char *) &MKparams->Bgbit, sizeof( int32_t));// Base bit gadget
        is.read((char *) &MKparams->dg, sizeof( int32_t));// dimension gadget
        is.read((char *) &MKparams->stdevBK, sizeof( double ));// BK standard deviation
        is.read((char *) &MKparams->parties, sizeof( int32_t));// number of parties
        is.read((char *) &MKparams->maskMod, sizeof(uint32_t));// Bg - 1
        is.read((char *) &MKparams->halfBg, sizeof( int32_t));// Bg/2
        is.read((char *) MKparams->g, sizeof( Torus32));// Bg/2
        is.read((char *) &MKparams->offset, sizeof( uint32_t));// offset = Bg/2 * (2^(32-Bgbit) + 2^(32-2*Bgbit) + ... + 2^(32-l*Bgbit))

        //bootstrapping key
        const int32_t n = MKparams->n;
        const int32_t parties = MKparams->parties;
        for (int i = 0; i < parties; ++i)
        {
            for (int j = 0; j < n; ++j)
            {
                MKTGswUESample_v2* bk_i = &bk[i*n+j];

                is.read((char *) &bk_i->party, sizeof( int32_t));
                is.read((char *) &bk_i->current_variance, sizeof( double));
                is.read((char *) &bk_i->dg, sizeof( int32_t));
                is.read((char *) &bk_i->N, sizeof( int32_t));

                for (int l = 0; l < 3 * bk_i->dg; l++) {
                    is.read((char *) &bk_i->d[l], sizeof(TorusPolynomial));
                }
//                f0 = d + dg;
//                f1 = d + 2*dg;
            }
        }

        //ksk
        for (int p = 0; p < parties; ++p)
        {
            LweKeySwitchKey* ks_i = &ks[p];
            const int32_t t = ks_i->t;
            const int32_t base = ks_i->base;

            is.read((char *) &ks_i->n, sizeof( int32_t));
            is.read((char *) &ks_i->t, sizeof( int32_t));
            is.read((char *) &ks_i->basebit, sizeof( int32_t));
            is.read((char *) &ks_i->base, sizeof( int32_t));


            for (int32_t i = 0; i < n; ++i) {
                for (int32_t j = 0; j < t; ++j) {
                    for (int32_t h = 0; h < base; ++h) {
                        is.read((char *) &ks_i->ks[i][j][h].current_variance, sizeof( double));
                        is.read((char *) &ks_i->ks[i][j][h].b, sizeof( Torus32));

                        for (int32_t z = 0; z < n; ++z)
                        {
                            is.read((char *) &ks_i->ks[i][j][h].a[z], sizeof( Torus32));
                        }
                    }
                }
            }

        }

    }

#ifdef __cplusplus
   MKLweBootstrappingKey_v2(const MKTFHEParams* MKparams, MKTGswUESample_v2* bk, 
        LweKeySwitchKey* ks);
    ~MKLweBootstrappingKey_v2();
    MKLweBootstrappingKey_v2(const MKLweBootstrappingKey_v2&) = delete;
    void operator=(const MKLweBootstrappingKey_v2&) = delete;
  
#endif
};



// alloc
EXPORT MKLweBootstrappingKey_v2 *alloc_MKLweBootstrappingKey_v2();
EXPORT MKLweBootstrappingKey_v2 *alloc_MKLweBootstrappingKey_v2_array(int32_t nbelts);
// free memory space 
EXPORT void free_MKLweBootstrappingKey_v2(MKLweBootstrappingKey_v2 *ptr);
EXPORT void free_MKLweBootstrappingKey_v2_array(int32_t nbelts, MKLweBootstrappingKey_v2 *ptr);
//initialize the structure
// in mkTFHEkeygen.h
// init_MKLweBootstrappingKey_v2(MKLweBootstrappingKey_v2 *obj, const int32_t n_in, 
//        const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT void init_MKLweBootstrappingKey_v2_array(int32_t nbelts, MKLweBootstrappingKey_v2 *obj,  
        const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
// destroys the structure
// in mkTFHEkeygen.h
// destroy_MKLweBootstrappingKey_v2(MKLweBootstrappingKey_v2 *obj);
EXPORT void destroy_MKLweBootstrappingKey_v2_array(int32_t nbelts, MKLweBootstrappingKey_v2 *obj);
// new = alloc + init
EXPORT MKLweBootstrappingKey_v2 *new_MKLweBootstrappingKey_v2(const LweParams* LWEparams, 
        const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT MKLweBootstrappingKey_v2 *new_MKLweBootstrappingKey_v2_array(int32_t nbelts,
        const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
// delete = destroy + free
EXPORT void delete_MKLweBootstrappingKey_v2(MKLweBootstrappingKey_v2 *obj);
EXPORT void delete_MKLweBootstrappingKey_v2_array(int32_t nbelts, MKLweBootstrappingKey_v2 *obj);











/*
 * MKLweBootstrappingKey is converted to a BootstrappingKeyFFT
 */
struct MKLweBootstrappingKeyFFT_v2 {
    const MKTFHEParams* MKparams; 
    MKTGswUESampleFFT_v2* bkFFT;
    LweKeySwitchKey* ks; //const MKLweKeySwitchKey* ks;

#ifdef __cplusplus
   MKLweBootstrappingKeyFFT_v2(const MKTFHEParams* MKparams, 
        MKTGswUESampleFFT_v2* bkFFT, LweKeySwitchKey* ks);
    ~MKLweBootstrappingKeyFFT_v2();
    MKLweBootstrappingKeyFFT_v2(const MKLweBootstrappingKeyFFT_v2&) = delete;
    void operator=(const MKLweBootstrappingKeyFFT_v2&) = delete;
  
#endif
};


// alloc
EXPORT MKLweBootstrappingKeyFFT_v2 *alloc_MKLweBootstrappingKeyFFT_v2();
EXPORT MKLweBootstrappingKeyFFT_v2 *alloc_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts);
// free memory space 
EXPORT void free_MKLweBootstrappingKeyFFT_v2(MKLweBootstrappingKeyFFT_v2 *ptr);
EXPORT void free_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts, MKLweBootstrappingKeyFFT_v2 *ptr);
//initialize the structure
// in mkTFHEkeygen.h
// EXPORT void init_MKLweBootstrappingKeyFFT_v2(MKLweBootstrappingKeyFFT_v2 *obj, const MKLweBootstrappingKey *bk,
//   const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT void init_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts, MKLweBootstrappingKeyFFT_v2 *obj, 
        const MKLweBootstrappingKey_v2 *bk, const LweParams* LWEparams, 
        const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
// destroys the structure
// in mkTFHEkeygen.h
// EXPORT void destroy_MKLweBootstrappingKeyFFT_v2(MKLweBootstrappingKeyFFT_v2 *obj);
EXPORT void destroy_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts, MKLweBootstrappingKeyFFT_v2 *obj);
// new = alloc + init
EXPORT MKLweBootstrappingKeyFFT_v2 *new_MKLweBootstrappingKeyFFT_v2(const MKLweBootstrappingKey_v2 *bk,
                                                                    const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT MKLweBootstrappingKeyFFT_v2 *new_MKLweBootstrappingKeyFFT_v2Single(const MKLweBootstrappingKey_v2 *bk,
                                                                          const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT MKLweBootstrappingKeyFFT_v2 *new_MKLweBootstrappingKeyFFT_v2Merged(std::vector<MKLweBootstrappingKeyFFT_v2*> bk,
                                                                          const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
EXPORT MKLweBootstrappingKey_v2 *new_MKLweBootstrappingKey_v2Merged(std::vector<MKLweBootstrappingKey_v2*> array,
                                                                    const MKTFHEParams* MKparams,
                                                                    const LweParams* LWEparams, const TLweParams* RLWEparams);
EXPORT MKLweBootstrappingKeyFFT_v2 *new_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts, const MKLweBootstrappingKey_v2 *bk,  
        const LweParams* LWEparams, const TLweParams* RLWEparams, const MKTFHEParams* MKparams);
// delete = destroy + free
EXPORT void delete_MKLweBootstrappingKeyFFT_v2(MKLweBootstrappingKeyFFT_v2 *obj);
EXPORT void delete_MKLweBootstrappingKeyFFT_v2_array(int32_t nbelts, MKLweBootstrappingKeyFFT_v2 *obj);






#endif //MKTFHEKEYS_H


