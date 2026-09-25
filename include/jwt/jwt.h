/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_JWT
#define NODEPP_JWT

/*────────────────────────────────────────────────────────────────────────────*/

#include <nodepp/nodepp.h>
#include <nodepp/encoder.h>
#include <nodepp/crypto.h>
#include <nodepp/json.h>

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace jwt { namespace HS256 {

    bool verify ( const string_t& token, const string_t& secret ){ do { 

        if( token .empty() ){ break; }
        if( secret.empty() ){ break; }

        auto data = regex::split( token, "\\." );
        if ( data.size() != 3 ) { break; }

        auto obj = json::parse( encoder::base64::btoa( data[0] ) );
        if( !obj["alg"].has_value() || obj["alg"].as<string_t>() != "HS256" )
          { break; } 

        string_t _token = string::join( ".", data[0], data[1] );
        auto sig = crypto::hmac::SHA256( secret ); sig.update( _token );
        auto ver = encoder::base64::atob( sig.get() ); return ver==data[2];

    } while(0); return false; }

    string_t encode( const string_t& payload, const string_t& secret ){

        string_t header = R"({"alg":"HS256","typ":"JWT"})";
        string_t token  = string::join( ".",
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload )
        );

        auto sig = crypto::hmac::SHA256( secret );
             sig.update( token );
        auto data= sig.get();

        return string::join( ".", 
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload ),
            encoder::base64::atob(    data )
        );

    }

    string_t decode ( const string_t& token ){ do {
        if( token.empty() ){ break; }

        auto data = regex::split( token, "\\." );
        if ( data.size() != 3 ) { break; }

        return encoder::base64::btoa( data[1] );

    } while(0); return nullptr; }

}}}

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace jwt { namespace HS384 {

    bool verify ( const string_t& token, const string_t& secret ){ do { 
        if( token .empty() ){ break; }
        if( secret.empty() ){ break; }

        auto data = regex::split( token, "\\." );
        if ( data.size() != 3 ) { break; }

        auto obj = json::parse( encoder::base64::btoa( data[0] ) );
        if( !obj["alg"].has_value() || obj["alg"].as<string_t>() != "HS384" )
          { break; } 

        string_t _token = string::join( ".", data[0], data[1] );;
        auto sig = crypto::hmac::SHA384( secret ); sig.update( _token );
        auto ver = encoder::base64::atob( sig.get() ); return ver==data[2];

    } while(0); return false; }

    string_t encode ( const string_t& payload, const string_t& secret ){

        string_t header = R"({"alg":"HS384","typ":"JWT"})";
        string_t token  = string::join( ".",
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload )
        );

        auto sig = crypto::hmac::SHA384( secret );
             sig.update( token );
        auto data= sig.get();

        return string::join( ".",
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload ),
            encoder::base64::atob(    data )
        );

    }

    string_t decode ( const string_t& token ){ return HS256::decode( token ); }

}}}

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace jwt { namespace HS512 {

    bool verify ( const string_t& token, const string_t& secret ){ do { 
        if( token .empty() ){ break; }
        if( secret.empty() ){ break; }

        auto data = regex::split( token, "\\." );
        if ( data.size() != 3 ) { break; }

        auto obj = json::parse( encoder::base64::btoa( data[0] ) );
        if( !obj["alg"].has_value() || obj["alg"].as<string_t>() != "HS512" )
          { break; } 

        string_t _token = string::join( ".", data[0], data[1] );;
        auto sig = crypto::hmac::SHA512( secret ); sig.update( _token );
        auto ver = encoder::base64::atob( sig.get() ); return ver==data[2];

    } while(0); return false; }

    string_t encode ( const string_t& payload, const string_t& secret ){

        string_t header = R"({"alg":"HS512","typ":"JWT"})";
        string_t token  = string::join( ".",
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload )
        );

        auto sig = crypto::hmac::SHA512( secret );
             sig.update( token );
        auto data= sig.get();

        return string::join( ".",
            encoder::base64::atob(  header ),
            encoder::base64::atob( payload ),
            encoder::base64::atob(    data )
        );

    }

    string_t decode ( const string_t& token ){ return HS256::decode( token ); }

}}}

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace jwt {

    string_t encode ( const string_t& token, const string_t& secret, const string_t& type="HS256" ){
        if  ( type=="HS256" ){ return HS256::encode( token, secret ); }
        elif( type=="HS384" ){ return HS384::encode( token, secret ); }
        elif( type=="HS512" ){ return HS512::encode( token, secret ); }
    return nullptr; }

    bool verify ( const string_t& token, const string_t& secret ){ do {

        auto data = regex::match( token, "[^.]+" ); 
        if ( data == nullptr ){ break; } 

        auto raw = json::parse( encoder::base64::btoa(data) );
        auto type= raw["alg"].as<string_t>().to_upper_case();

        if  ( type=="HS256" ){ return HS256::verify( token, secret ); }
        elif( type=="HS384" ){ return HS384::verify( token, secret ); }
        elif( type=="HS512" ){ return HS512::verify( token, secret ); } 
        
    } while(0); return false; }

    string_t decode ( const string_t& token ){ return HS256::decode( token ); }

}}

/*────────────────────────────────────────────────────────────────────────────*/

#endif