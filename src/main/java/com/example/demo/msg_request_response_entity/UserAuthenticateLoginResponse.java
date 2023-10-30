package com.example.demo.msg_request_response_entity;

public class UserAuthenticateLoginResponse {

    private String jwt;

    public UserAuthenticateLoginResponse(String jwt) {
        this.jwt = jwt;
    }

    public UserAuthenticateLoginResponse() { }

    public String getJwt() {
        return jwt;
    }
    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

}
