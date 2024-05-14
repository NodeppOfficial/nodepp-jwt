#ifndef NODEPP_JWT
#define NODEPP_JWT

#include <nodepp/nodepp.h>
#include <nodepp/crypto.h>
#include <nodepp/encoder.h>

namespace nodepp { namespace jwt {

    bool verify ( const string_t& token, const string_t& secret ){

        auto data = regex::split( token, '.' );
        if ( data.size() != 3 ){ return false; }

        string_t _token = string::format("%s.%s",data[0].get(),data[1].get());
        auto sig = crypto::hmac::SHA256( secret ); sig.update( _token );
        auto ver = encoder::base64::get( sig.get() );

        return ver == data[2];

    }

    string_t encode ( const string_t& payload, string_t secret ){

        string_t header = R"({"alg":"HS256","typ":"JWT"})";
        string_t token  = string::format("%s.%s",
            encoder::base64::get(  header ).get(),
            encoder::base64::get( payload ).get()
        );

        auto sig = crypto::hmac::SHA256( secret );
             sig.update( token );
        auto data= sig.get();

        return string::format("%s.%s.%s",
            encoder::base64::get(  header.get() ).get(),
            encoder::base64::get( payload.get() ).get(),
            encoder::base64::get(    data.get() ).get()
        );

    }

    string_t decode ( const string_t& token ){

        auto data = regex::split( token, '.' );
        if ( data.size() != 3 )
           { process::error("invalid token"); }

        return encoder::base64::set( data[1] );

    }

}}

#endif