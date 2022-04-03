//#include <stdio.h>
#include <iostream>
//#include <iomanip>
#include <cstdlib>
//#include <cmath>
#include <fstream>
#include <sys/time.h>
#include "tfhe.h"
#include "polynomials.h"
//#include "lwesamples.h"
//#include "lwekey.h"
#include "lweparams.h"
#include "tlwe.h"
//#include "tgsw.h"
#include <sys/types.h>
#include <sys/stat.h>

#include "mkTFHEparams.h"
#include "mkTFHEkeys.h"
#include "mkTFHEkeygen.h"
#include "mkTFHEsamples.h"
#include "mkTFHEfunctions.h"





 

using namespace std;

// **********************************************************************************
// **************************** STATIC PARAMETERS ***********************************
// **********************************************************************************

// generate params
static const int32_t k = 1;
static const double ks_stdev = 3.05e-5;// 2.44e-5; //standard deviation
static const double bk_stdev = 3.72e-9; // 3.29e-10; //standard deviation
static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space
static const int32_t n = 560; //500;            // LWE modulus
static const int32_t n_extract = 1024;    // LWE extract modulus (used in bootstrapping)
//    static const int32_t hLWE = 0;         // HW secret key LWE --> not used
static const double stdevLWE = 0.012467;      // LWE ciphertexts standard deviation
static const int32_t Bksbit = 2;       // Base bit key switching
static const int32_t dks = 8;          // dimension key switching
static const double stdevKS = ks_stdev; // 2.44e-5;       // KS key standard deviation
static const int32_t N = 1024;            // RLWE,RGSW modulus
static const int32_t hRLWE = 0;        // HW secret key RLWE,RGSW --> not used
static const double stdevRLWEkey = bk_stdev; // 3.29e-10; // 0; // 0.012467;  // RLWE key standard deviation
static const double stdevRLWE = bk_stdev; // 3.29e-10; // 0; // 0.012467;     // RLWE ciphertexts standard deviation
static const double stdevRGSW = bk_stdev; // 3.29e-10;     // RGSW ciphertexts standard deviation
static const int32_t Bgbit = 8;        // Base bit gadget
static const int32_t dg = 4;           // dimension gadget
static const double stdevBK = bk_stdev; // 3.29e-10;       // BK standard deviation
static const int32_t parties = 4;      // number of parties

// new parameters
// 2 parties, B=2^9, d=3 -> works
// 4 parties, B=2^8, d=4 -> works
// 8 parties, B=2^6, d=5 -> works



// **********************************************************************************
// ********************************* MAIN *******************************************
// **********************************************************************************


void dieDramatically(string message) {
    cerr << message << endl;
    abort();
}

static void gen_keys(int ID)
{
    cout << "Create keys folder" << endl;
    mkdir("./keys", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    // Key generation
    cout << "Starting KEY GENERATION" << endl;
    //TODO: set random generator

    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);
    // load common key
    MKRLweKey* dPK = new_MKRLweKey(RLWEparams, MKparams);
    //TODO: error handlingd
    dPK->deserialize("keys/CommonKey.binary");

    MKparams->hLWE = ID - 1;
    cout << "Reading \"CommonKey.binary\": DONE!" << endl;

    // LWE key
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    MKLweKeyGenSingle(MKlwekey);
    MKlwekey->serialize("keys/Secret.binary");
    cout << "KeyGen MKlwekey: DONE!" << endl;

    // RLWE key
    MKRLweKey* MKrlwekey = new_MKRLweKey(RLWEparams, MKparams);
    MKRLweKeyGenSingle(MKrlwekey, dPK);
    //        Try serialization
    MKrlwekey->serialize("keys/Public.binary");

    cout << "KeyGen MKRlwekey: DONE!" << endl;

    // LWE key extracted
    MKLweKey* MKextractedlwekey = new_MKLweKey(extractedLWEparams, MKparams);
    MKtLweExtractKeySingle(MKextractedlwekey, MKrlwekey);
    cout << "Extract MKextractedlwekey: DONE!" << endl;

    // bootstrapping + key switching keys
    MKLweBootstrappingKey_v2* MKlweBK = new_MKLweBootstrappingKey_v2(LWEparams, RLWEparams, MKparams);
    MKlweCreateBootstrappingKey_v2Single(MKlweBK, MKlwekey, MKrlwekey, MKextractedlwekey,
                                         extractedLWEparams, LWEparams, RLWEparams, MKparams);
    //        Try serialization
    MKlweBK->serialize("keys/KSKBSK.binary");

    cout << "KeyGen MKlweBK: DONE!" << endl;
    cout << "Finished KEY GENERATION" << endl;

    delete_MKLweBootstrappingKey_v2(MKlweBK);
    delete_MKLweKey(MKextractedlwekey);
    delete_MKRLweKey(MKrlwekey);
    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
    delete_LweParams(extractedLWEparams);

}

static void first_enc_bits(string BITS)
{
    // Key generation
    cout << "Starting FIRST BIT ENCRYPTION" << endl;

//    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);

    // LWE key
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    //        Try deserialization
    MKlwekey->deserialize("keys/Secret.binary");
    cout << "Reading MKlwekey: DONE!" << endl;

    {
        char buffer [50];
        sprintf (buffer, "sampleSeq%d.binary", MKlwekey->MKparams->hLWE + 1);
        fstream myfile = fstream(buffer, ios::out | ios::binary);

        for (uint i = 0; i < BITS.size(); i++) {
            MKLweSample *sample = new_MKLweSample(LWEparams, MKparams);
            if (BITS[i] == '0') {
                MKbootsSymEncryptSingleFirst(sample, 0, MKlwekey);
            } else {
                MKbootsSymEncryptSingleFirst(sample, 1, MKlwekey);
            }
            sample->current_variance = stdevLWE*stdevLWE;
            sample->serialize(&myfile);
        }
    }

    cout << "First encryption: DONE!" << endl;

    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
}

static void next_enc_bits(string path, int32_t b)
{
    // Key generation
    cout << "Starting NEXT BIT ENCRYPTION" << endl;

//    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);

    // LWE key
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    //        Try deserialization
    MKlwekey->deserialize("keys/Secret.binary");
    cout << "Reading MKlwekey: DONE!" << endl;

//    {
//        fstream myfile = fstream(path, ios::out | ios::in | ios::binary);
//
//        for (int i = 0; i < b; i++) {
//            MKLweSample *sample = new_MKLweSample(LWEparams, MKparams);
//            sample->deserialize(&myfile);
//            MKbootsSymEncryptSingle(sample, MKlwekey);
//            sample->current_variance = stdevLWE*stdevLWE;
//            sample->serialize(&myfile);
//        }
//    }

    std::vector<MKLweSample *> lweArray;
    {
        fstream infile = fstream(path, ios::in | ios::binary);

        for (int i = 0; i < b; i++) {
            MKLweSample *sample = new_MKLweSample(LWEparams, MKparams);
            sample->deserialize(&infile);
            lweArray.push_back(sample);
        }
    }
    {
        fstream outfile = fstream(path, ios::out | ios::binary);
        for (int i = 0; i < b; i++) {
            MKbootsSymEncryptSingle(lweArray[i], MKlwekey);
            lweArray[i]->serialize(&outfile);
        }
    }

    cout << "Next bit encryption: DONE!" << endl;

    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
}

static void next_dec_bits(string path, int32_t b)
{
    // Key generation
    cout << "Starting BIT DECRYPTION" << endl;

//    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);

    // LWE key
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    //        Try deserialization
    MKlwekey->deserialize("keys/Secret.binary");
    cout << "Reading MKlwekey: DONE!" << endl;
    std::vector<MKLweSample *> lweArray;
    {
        fstream infile = fstream(path, ios::in | ios::binary);

        for (int i = 0; i < b; i++) {
            MKLweSample *sample = new_MKLweSample(LWEparams, MKparams);
            sample->deserialize(&infile);
            lweArray.push_back(sample);
        }
    }
    {
        fstream outfile = fstream(path, ios::out | ios::binary);
        for (int i = 0; i < b; i++) {
            MKbootsSymDecryptSingle(lweArray[i], MKlwekey);
            lweArray[i]->serialize(&outfile);
        }
    }

    cout << "Next decryption: DONE!" << endl;

    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
}

static void finalize_bits(string path, int32_t b)
{
    // Key generation
    cout << "Starting BIT DECRYPTION FINALIZATION" << endl;

//    LweParams *extractedLWEparams = new_LweParams(n_extract, ks_stdev, max_stdev);
    LweParams *LWEparams = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *RLWEparams = new_TLweParams(N, k, bk_stdev, max_stdev);
    MKTFHEParams *MKparams = new_MKTFHEParams(n, n_extract, 0, stdevLWE, Bksbit, dks, stdevKS, N,
                                              hRLWE, stdevRLWEkey, stdevRLWE, stdevRGSW, Bgbit, dg, stdevBK, parties);

    // LWE key
    MKLweKey* MKlwekey = new_MKLweKey(LWEparams, MKparams);
    //        Try deserialization
    MKlwekey->deserialize("keys/Secret.binary");
    cout << "Reading MKlwekey: DONE!" << endl;

    {
        fstream myfile = fstream(path, ios::in | ios::binary);
        cout << "Finalized result: " << endl;

        for (int i = 0; i < b; i++) {
            MKLweSample *sample = new_MKLweSample(LWEparams, MKparams);
            sample->deserialize(&myfile);
            cout << MKbootsSymDecryptSingleFinalize(sample);
        }
        cout << endl;
    }

    cout << "Bit decrypt finaliztion: DONE!" << endl;

    delete_MKLweKey(MKlwekey);
    // delete params
    delete_MKTFHEParams(MKparams);
    delete_TLweParams(RLWEparams);
    delete_LweParams(LWEparams);
}

static void show_usage(string name)
{
    cerr << "Usage: " << name << " OPTION\n"
    << "Options:\n"
    << "\tg (1 | 2 | 3 | 4)\tGenerate keys for party with ID - Secret, Public, Bootstrapping, KeySwitching" << endl
    << "\te (0 | 1)*\tCreate encrypted bit string (6 bits, ex. 101001)" << endl
    << "\tn /dat.binary\tContinue encryption of bit string" << endl
    << "\td /dat.binary\tContinue decryption of bit string" << endl
    << "\tf /dat.binary\tFinalize decryption and print out result" << endl
//    << "\te (0 | 1)*\tEncrypt bit string (6 bits, ex. 101001) and save it" << endl
    << endl;
}

int32_t main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }
    vector <string> sources;
    string destination;

    switch (*argv[1])
    {
        default: {
            printf("Unknown option -%c\n\n", (*argv)[1]);
            break;
        }
        case 'e': {
            first_enc_bits(argv[2]);
            break;
        }
        case 'n': {
            next_enc_bits(argv[2], 6);
            break;
        }
        case 'f': {
            finalize_bits(argv[2], 6);
            break;
        }
        case 'd': {
            next_dec_bits(argv[2], 6);
            break;
        }
        case 'g': {
            string ID = argv[2];
            int id = std::stoi(ID);
            if (id >= 1 && id <= 4) {
                gen_keys(id);
            } else {
                cerr << endl << "IDs 1-4 are supported only" << endl;
                return 1;
            }
            break;
        }
    }


    return 0;
}
