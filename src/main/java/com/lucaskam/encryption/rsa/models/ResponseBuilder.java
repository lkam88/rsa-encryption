package com.lucaskam.encryption.rsa.models;

public class ResponseBuilder {
    private Response response = new Response();
    
    public ResponseBuilder message(String message) {
        response.setMessage(message);
        return this;
    }

    public ResponseBuilder signature(String signature) {
        response.setSignature(signature);
        return this;
    }

    public ResponseBuilder pubKey(String pubKey) {
        response.setPubKey(pubKey);
        return this;
    }

    public Response build() {
        return response;
    }
}
