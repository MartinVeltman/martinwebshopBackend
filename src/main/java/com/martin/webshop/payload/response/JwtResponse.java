package com.martin.webshop.payload.response;

import java.util.List;

public class JwtResponse {
    private String token;

    public JwtResponse(String accesToken) {
        this.token = accesToken;
    }

    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }


}
