package com.example.demo.msg_request_response_entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.annotation.Generated;

@JsonIgnoreProperties//za request stavitiali i ne mora. OVA KLASA SAMO PRIHVATA PODATKE SA NPR POSTMANA, RADICE I BEZ SVIH OVIH ANOTACIJA
@Generated("com.robohorse.robopojogenerator")
public class UserAuthenticateLoginRequest {

    @JsonProperty
    private String username;
    @JsonProperty
    private String password;

    public UserAuthenticateLoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public UserAuthenticateLoginRequest(){}

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
